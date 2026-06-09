//! OCSP signature verification, and reading a stapled OCSP response (RFC 5940)
//! embedded in `SignedData.crls` as a revocation signal for the signer certificate

use crate::cryptography_x509::certificate::Certificate;
use crate::cryptography_x509::common::{AlgorithmIdentifier, Asn1Read};
use crate::cryptography_x509::extensions::AuthorityKeyIdentifier;
use crate::cryptography_x509::name::Name;
use crate::cryptography_x509::ocsp_req::CertID;
use crate::cryptography_x509::ocsp_resp::{BasicOCSPResponse, CertStatus, OCSPResponse, ResponderId, Response, SingleResponse};
use crate::cryptography_x509::oid;
use crate::cryptography_x509::pkcs7::{RevocationInfoChoice, SignedData};
use crate::cryptography_x509_verification::ops::CryptoOps;
use crate::cryptography_x509_verification::policy::SMIME_PERMITTED_SIGNATURE_ALGORITHMS;
use crate::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm;
use crate::types::KeyCryptoOps;
use crate::utils::asn1_to_chrono;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tsify::Tsify;

/// Why an OCSP response could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspError {
    /// DER-encoding a value we needed to hash or verify failed.
    Encoding(String),
    /// Signature algorithm not on the S/MIME permitted list.
    DisallowedAlgorithm,
    /// No valid signature from the issuer or an authorized responder.
    SignatureInvalid,
    /// A field could not be interpreted (e.g. an unparseable date).
    Malformed(String),
}

/// The certificate status asserted by a verified stapled OCSP response
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Tsify)]
#[serde(rename_all = "lowercase")]
pub enum StapledStatus {
    Good,
    Revoked,
    Unknown,
}

/// A stapled OCSP response extracted from `SignedData.crls`
pub struct StapledOcsp<'a> {
    pub basic: BasicOCSPResponse<'a>,
}

impl<'a> StapledOcsp<'a> {
    /// The individual certificate statuses carried by this response
    pub fn single_responses(&self) -> impl Iterator<Item = SingleResponse<'a>> + '_ {
        self.basic.tbs_response_data.responses.unwrap_read().clone()
    }
}

pub fn sha1_of(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn names_match(a: &Name<'_>, b: &Name<'_>) -> Result<bool, OcspError> {
    let a_der = asn1::write_single(a).map_err(|_| OcspError::Encoding("name".into()))?;
    let b_der = asn1::write_single(b).map_err(|_| OcspError::Encoding("name".into()))?;
    Ok(a_der == b_der)
}

pub fn get_ski<'a>(cert: &'a Certificate<'a>) -> Option<&'a [u8]> {
    cert.extensions().ok()?.get_extension(&oid::SUBJECT_KEY_IDENTIFIER_OID).and_then(|ext| ext.value::<&[u8]>().ok())
}

fn get_aki_key_identifier(cert: &Certificate<'_>) -> Option<Vec<u8>> {
    cert.extensions()
        .ok()?
        .get_extension(&oid::AUTHORITY_KEY_IDENTIFIER_OID)
        .and_then(|ext| ext.value::<AuthorityKeyIdentifier<'_, Asn1Read>>().ok())
        .and_then(|aki| aki.key_identifier.map(|k| k.to_vec()))
}

/// If the child has an AKI, require it to match the issuer's SKI (or SHA-1 of its public key)
pub fn check_aki_matches_issuer(child: &Certificate<'_>, issuer: &Certificate<'_>) -> Result<(), OcspError> {
    let Some(aki_key_id) = get_aki_key_identifier(child) else {
        return Ok(());
    };
    let issuer_id =
        get_ski(issuer).map(|s| s.to_vec()).unwrap_or_else(|| sha1_of(issuer.tbs_cert.spki.subject_public_key.as_bytes()).to_vec());
    if aki_key_id != issuer_id {
        return Err(OcspError::SignatureInvalid);
    }
    Ok(())
}

pub fn check_algorithm_permitted(alg: &AlgorithmIdentifier<'_>) -> Result<(), OcspError> {
    if SMIME_PERMITTED_SIGNATURE_ALGORITHMS.contains(alg) { Ok(()) } else { Err(OcspError::DisallowedAlgorithm) }
}

/// A certificate's validity window as chrono instants (unparseable dates -> None)
fn cert_validity(cert: &Certificate<'_>) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    Some((
        asn1_to_chrono(cert.tbs_cert.validity.not_before.as_datetime())?,
        asn1_to_chrono(cert.tbs_cert.validity.not_after.as_datetime())?,
    ))
}

/// A `nextUpdate`-less OCSP response is honored for at most this long after `thisUpdate`.
const MAX_AGE_WITHOUT_NEXT_UPDATE_DAYS: i64 = 7;

/// Whether a single OCSP response is fresh at `now` and may be honored. `thisUpdate` must
/// not be in the future; the assertion is valid until `nextUpdate`, or - when `nextUpdate`
/// is absent (RFC 6960 §3.2 leaves its lifetime to the relying party) - for at most 7 days
/// after `thisUpdate`. In no case is it honored outside the signing responder's own validity
/// window: a response can't be good before the responder exists or after it expires.
/// Unparseable dates -> false (fail closed).
fn single_response_fresh(single: &SingleResponse<'_>, now: DateTime<Utc>, responder_validity: (DateTime<Utc>, DateTime<Utc>)) -> bool {
    let Some(this_update) = asn1_to_chrono(single.this_update.as_datetime()) else {
        return false;
    };
    if now < this_update {
        return false;
    }
    let window_end = match &single.next_update {
        Some(nu) => match asn1_to_chrono(nu.as_datetime()) {
            Some(next_update) => next_update,
            None => return false,
        },
        None => this_update + chrono::Duration::days(MAX_AGE_WITHOUT_NEXT_UPDATE_DAYS),
    };
    let (responder_not_before, responder_not_after) = responder_validity;
    now <= window_end && now >= responder_not_before && now <= responder_not_after
}

/// Verify `basic_resp` was signed by `issuer` directly, or by a delegated responder
/// it authorized; the signing cert must be valid at `now`. Returns the signing cert's
/// validity window so the caller can bound how long the response may be honored.
pub fn verify_ocsp_signature(
    basic_resp: &BasicOCSPResponse<'_>,
    issuer: &Certificate<'_>,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), OcspError> {
    let ops = KeyCryptoOps {};

    let tbs_der = asn1::write_single(&basic_resp.tbs_response_data).map_err(|_| OcspError::Encoding("OCSP TBS response data".into()))?;

    check_algorithm_permitted(&basic_resp.signature_algorithm)?;

    let issuer_spki_hash = sha1_of(issuer.tbs_cert.spki.subject_public_key.as_bytes());
    let issuer_matches_responder_id = match &basic_resp.tbs_response_data.responder_id {
        ResponderId::ByName(name) => names_match(name, &issuer.tbs_cert.subject)?,
        ResponderId::ByKey(hash) => *hash == issuer_spki_hash.as_slice(),
    };

    let issuer_pubkey = ops.public_key(issuer).map_err(|e| OcspError::Malformed(format!("issuer public key: {e}")))?;

    if issuer_matches_responder_id {
        if let Some((nb, na)) = cert_validity(issuer) {
            if now >= nb
                && now <= na
                && verify_signature_with_signature_algorithm(
                    &issuer_pubkey,
                    &basic_resp.signature_algorithm,
                    basic_resp.signature.as_bytes(),
                    &tbs_der,
                )
                .is_ok()
            {
                return Ok((nb, na));
            }
        }
    }

    if let Some(certs) = &basic_resp.certs {
        for cert in certs.unwrap_read().clone() {
            let candidate_matches = match &basic_resp.tbs_response_data.responder_id {
                ResponderId::ByName(name) => names_match(name, &cert.tbs_cert.subject)?,
                ResponderId::ByKey(hash) => *hash == sha1_of(cert.tbs_cert.spki.subject_public_key.as_bytes()).as_slice(),
            };
            if !candidate_matches {
                continue;
            }

            if !names_match(&cert.tbs_cert.issuer, &issuer.tbs_cert.subject)? {
                continue;
            }
            if check_aki_matches_issuer(&cert, issuer).is_err() {
                continue;
            }
            if check_algorithm_permitted(&cert.signature_alg).is_err() {
                continue;
            }

            let Ok(cert_tbs_der) = asn1::write_single(&cert.tbs_cert) else {
                continue;
            };
            if verify_signature_with_signature_algorithm(&issuer_pubkey, &cert.signature_alg, cert.signature.as_bytes(), &cert_tbs_der)
                .is_err()
            {
                continue;
            }

            let Ok(extensions) = cert.extensions() else {
                continue;
            };
            let has_ocsp_signing = extensions
                .get_extension(&oid::EXTENDED_KEY_USAGE_OID)
                .and_then(|ext| ext.value::<asn1::SequenceOf<'_, asn1::ObjectIdentifier>>().ok())
                .map(|ekus| ekus.into_iter().any(|eku| eku == oid::EKU_OCSP_SIGNING_OID))
                .unwrap_or(false);
            let has_no_check = extensions.get_extension(&oid::OCSP_NO_CHECK_OID).is_some();
            if !(has_ocsp_signing && has_no_check) {
                continue;
            }

            let Some((nb, na)) = cert_validity(&cert) else {
                continue;
            };
            if now < nb || now > na {
                continue;
            }

            let Ok(responder_pubkey) = ops.public_key(&cert) else {
                continue;
            };
            if verify_signature_with_signature_algorithm(
                &responder_pubkey,
                &basic_resp.signature_algorithm,
                basic_resp.signature.as_bytes(),
                &tbs_der,
            )
            .is_ok()
            {
                return Ok((nb, na));
            }
        }
    }

    Err(OcspError::SignatureInvalid)
}

/// Whether an OCSP `CertID` (RFC 6960) identifies `leaf` as issued by `issuer`.
/// The CertID names its own hash algorithm; SHA-1 and SHA-256 are recognised.
pub fn cert_id_matches(cert_id: &CertID<'_>, leaf: &Certificate<'_>, issuer: &Certificate<'_>) -> bool {
    let Ok(issuer_name_der) = asn1::write_single(&leaf.tbs_cert.issuer) else {
        return false;
    };
    let issuer_key_bits = issuer.tbs_cert.spki.subject_public_key.as_bytes();
    let alg = cert_id.hash_algorithm.oid();
    let (issuer_name_hash, issuer_key_hash) = if *alg == oid::SHA1_OID {
        (sha1_of(&issuer_name_der).to_vec(), sha1_of(issuer_key_bits).to_vec())
    } else if *alg == oid::SHA256_OID {
        (sha256_of(&issuer_name_der).to_vec(), sha256_of(issuer_key_bits).to_vec())
    } else {
        return false;
    };

    cert_id.issuer_name_hash == issuer_name_hash.as_slice()
        && cert_id.issuer_key_hash == issuer_key_hash.as_slice()
        && cert_id.serial_number == leaf.tbs_cert.serial
}

/// Extract stapled OCSP responses (RFC 5940 `OtherRevocationInfoFormat` with
/// `id-ri-ocsp-response`) from a `SignedData`, skipping malformed/non-successful ones.
pub fn extract_stapled_ocsp<'a>(signed_data: &'a SignedData<'a>) -> Vec<StapledOcsp<'a>> {
    let mut out = Vec::new();
    let Some(crls) = signed_data.crls.as_ref() else {
        return out;
    };
    for choice in crls.unwrap_read().clone() {
        let RevocationInfoChoice::Other(other) = choice else {
            continue;
        };
        if other.other_rev_info_format != oid::RI_OCSP_OID {
            continue;
        }
        let Ok(ocsp_resp) = asn1::parse_single::<OCSPResponse<'a>>(other.other_rev_info.full_data()) else {
            continue;
        };
        if ocsp_resp.response_status.value() != 0 {
            continue;
        }
        let Some(bytes) = ocsp_resp.response_bytes else {
            continue;
        };
        let basic = match bytes.response {
            Response::Basic(r) => r.into_inner(),
        };
        out.push(StapledOcsp { basic });
    }
    out
}

/// The stapled OCSP status for `leaf` from the first staple with a matching certID
/// signed by `issuer` (the trust-anchored issuer) or a responder it authorized;
/// `None` otherwise
pub fn stapled_status_for(
    staples: &[StapledOcsp<'_>],
    leaf: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: DateTime<Utc>,
) -> Option<StapledStatus> {
    let mut first_non_revoked = None;
    for stapled in staples {
        let Some(single) = stapled.single_responses().find(|s| cert_id_matches(&s.cert_id, leaf, issuer)) else {
            continue;
        };
        let Ok(responder_validity) = verify_ocsp_signature(&stapled.basic, issuer, now) else {
            continue;
        };
        if !single_response_fresh(&single, now, responder_validity) {
            continue;
        }
        match single.cert_status {
            // A valid revocation proof always wins, never shadowed by a coexisting fresh Good/Unknown.
            CertStatus::Revoked(_) => return Some(StapledStatus::Revoked),
            CertStatus::Good(_) => first_non_revoked.get_or_insert(StapledStatus::Good),
            CertStatus::Unknown(_) => first_non_revoked.get_or_insert(StapledStatus::Unknown),
        };
    }
    first_non_revoked
}
