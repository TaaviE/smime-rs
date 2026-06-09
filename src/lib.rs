pub mod types;
pub mod utils;

pub mod cms_utils;

#[path = "../vendor/pyca-cryptography/cryptography-x509/lib.rs"]
pub mod cryptography_x509;

#[path = "../vendor/pyca-cryptography/cryptography-x509-verification/lib.rs"]
pub mod cryptography_x509_verification;

#[path = "../vendor/pyca-cryptography/cryptography-x509-verify/lib.rs"]
pub mod cryptography_x509_verify;

#[cfg(feature = "decrypt")]
pub mod decrypt;
#[cfg(feature = "decrypt")]
mod decrypt_verify;
#[cfg(feature = "encrypt")]
pub mod encrypt;
pub mod errors;
#[cfg(feature = "decrypt")]
pub mod pkcs12_utils;

use crate::cryptography_x509::certificate::Certificate;
use crate::cryptography_x509::common::{Asn1Read, Time};
use crate::cryptography_x509::extensions::{PolicyInformation, Qualifier, SubjectAlternativeName};
use crate::cryptography_x509::name::GeneralName;
use crate::cryptography_x509::oid::*;
use crate::cryptography_x509::pkcs7::{CmsAlgorithmProtection, Content, ContentInfo, PKCS7_DATA_OID, SignerInfo};
use crate::cryptography_x509_verification::ops::CryptoOps;
use crate::cryptography_x509_verification::policy::SMIME_PERMITTED_SIGNATURE_ALGORITHMS;
use crate::cryptography_x509_verify::sign::{
    HashType, SignatureParameters, hash_oid_to_hash_type, identify_signature_algorithm_parameters,
};
use crate::cryptography_x509_verify::{OwnedCertificate, PolicyBuilder, PyStore};
use crate::errors::SmimeError;
use crate::types::KeyCryptoOps;
use crate::utils::set_panic_hook;
use chrono::{DateTime, Duration, TimeZone, Utc};
#[cfg(feature = "decrypt")]
pub use decrypt_verify::decrypt_and_verify_smime_from_eml_detailed;
use mail_parser::{MessageParser, MimeHeaders};
use pem::Pem;
pub use types::{
    AnyPublicKey, CryptographyResult, SignatureChecks, SignerValidation, SigningSystem, SmimeValidationResult, TrustConfig, TrustStore,
    ValidationDetails,
};

use crate::cryptography_x509_verification::policy;
use asn1::ObjectIdentifier;
use utils::{ber_to_der_cms, extract_first_multipart_part_raw};
use wasm_bindgen::prelude::*;

fn sha256_fingerprint_hex(cert: &Certificate<'_>) -> Option<String> {
    use sha2::Digest;
    let der = asn1::write_single(cert).ok()?;
    let digest = sha2::Sha256::digest(&der);
    Some(hex::encode(digest.as_slice()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    fn log(s: &str);

    #[wasm_bindgen(typescript_type = "SmimeValidationResult")]
    pub type JsSmimeValidationResult;
}

#[wasm_bindgen(typescript_custom_section)]
const TS_SMIME_ERROR: &'static str = r#"
export interface SmimeError {
    id: string;
    args: Map<string, string>;
}
"#;

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (println!($($t)*))
}

#[wasm_bindgen]
pub fn verify_smime_from_eml(eml_text: js_sys::JsString) -> JsSmimeValidationResult {
    set_panic_hook();

    let eml_string = eml_text.as_string().unwrap();

    let result = verify_smime_from_eml_detailed(eml_string, vec![TrustStore::Builtin].into());

    for failure in &result.failures {
        console_log!("{}", failure.localize_en_uk());
    }
    for signer in &result.signers {
        for note in &signer.validation_details.other_notes {
            console_log!("{}", note.localize_en_uk());
        }
    }

    serde_wasm_bindgen::to_value(&result).unwrap().unchecked_into()
}

/// Encrypt to recipients using AES-256-GCM (CMS AuthEnvelopedData).
/// Returns DER ContentInfo bytes, or `undefined` if no recipient cert had a usable key.
#[cfg(feature = "encrypt")]
#[wasm_bindgen]
pub fn encrypt_gcm(certs_pem: Vec<String>, plaintext: &[u8], pkcs1v15: bool) -> Result<Option<Vec<u8>>, JsError> {
    set_panic_hook();
    encrypt::encrypt(&certs_pem, plaintext, encrypt::ContentCipher::Aes256Gcm, pkcs1v15).map_err(|e| JsError::new(&e.localize_en_uk()))
}

/// Encrypt to recipients using AES-256-CBC (CMS EnvelopedData).
/// Returns DER ContentInfo bytes, or `undefined` if no recipient cert had a usable key.
#[cfg(feature = "encrypt")]
#[wasm_bindgen]
pub fn encrypt_cbc(certs_pem: Vec<String>, plaintext: &[u8], pkcs1v15: bool) -> Result<Option<Vec<u8>>, JsError> {
    set_panic_hook();
    encrypt::encrypt(&certs_pem, plaintext, encrypt::ContentCipher::Aes256Cbc, pkcs1v15).map_err(|e| JsError::new(&e.localize_en_uk()))
}

/// Validate a recipient certificate's public key (RSA 2048-4096, or EC P-256/384/521).
/// Throws if the key is unsupported.
#[cfg(feature = "encrypt")]
#[wasm_bindgen]
pub fn validate_cert_key(cert_pem: &str) -> Result<(), JsError> {
    set_panic_hook();
    encrypt::validate_cert_key(cert_pem).map_err(|e| JsError::new(&e.localize_en_uk()))
}

fn asn1_time_to_chrono(time: &Time) -> Option<DateTime<Utc>> {
    let dt = time.as_datetime();
    Utc.with_ymd_and_hms(dt.year() as i32, dt.month() as u32, dt.day() as u32, dt.hour() as u32, dt.minute() as u32, dt.second() as u32)
        .single()
}

fn mail_parser_date_to_chrono(d: &mail_parser::DateTime) -> Option<DateTime<Utc>> {
    Utc.with_ymd_and_hms(d.year as i32, d.month as u32, d.day as u32, d.hour as u32, d.minute as u32, d.second as u32).single().map(|dt| {
        let offset_mins = (d.tz_hour as i32) * 60 + (d.tz_minute as i32);
        if d.tz_before_gmt { dt + Duration::minutes(offset_mins as i64) } else { dt - Duration::minutes(offset_mins as i64) }
    })
}

pub use utils::email_domain_to_a_label;

fn load_ca_certs(trust_stores: &[TrustStore], ca_file_pem: Option<&[u8]>) -> Result<Vec<OwnedCertificate>, SmimeError> {
    let mut ca_certs: Vec<OwnedCertificate> = Vec::new();

    let mut load_bundle = |bundle: &[u8], label: &str| -> Result<(), SmimeError> {
        let blocks = pem::parse_many(bundle).map_err(|e| SmimeError::LoadCaBundle { store: label.to_string(), err: e.to_string() })?;
        for pem_block in blocks {
            if pem_block.tag().eq_ignore_ascii_case("CERTIFICATE") {
                let der: Vec<u8> = pem_block.into_contents();
                if let Ok(owned) = OwnedCertificate::try_new(der, |d| asn1::parse_single(d)) {
                    ca_certs.push(owned);
                }
            }
        }
        Ok(())
    };

    for store_type in trust_stores {
        let ca_pem_bundle = match store_type {
            TrustStore::Builtin => include_str!("ca_certs.pem"),
            TrustStore::Debug => include_str!("ca_certs_debug.pem"),
        };
        load_bundle(ca_pem_bundle.as_bytes(), &format!("{:?}", store_type))?;
    }

    if let Some(bundle) = ca_file_pem {
        load_bundle(bundle, "CAfile")?;
    }

    Ok(ca_certs)
}

const SMIME_BR_OIDS: [ObjectIdentifier; 12] = [
    CABF_MAILBOX_VALIDATED_LEGACY,
    CABF_MAILBOX_VALIDATED_MULTIPURPOSE,
    CABF_MAILBOX_VALIDATED_STRICT,
    CABF_ORGANIZATION_VALIDATED_LEGACY,
    CABF_ORGANIZATION_VALIDATED_MULTIPURPOSE,
    CABF_ORGANIZATION_VALIDATED_STRICT,
    CABF_SPONSOR_VALIDATED_LEGACY,
    CABF_SPONSOR_VALIDATED_MULTIPURPOSE,
    CABF_SPONSOR_VALIDATED_STRICT,
    CABF_INDIVIDUAL_VALIDATED_LEGACY,
    CABF_INDIVIDUAL_VALIDATED_MULTIPURPOSE,
    CABF_INDIVIDUAL_VALIDATED_STRICT,
];
fn extract_cert_info(cert: &Certificate<'_>) -> (Vec<String>, Vec<String>, Vec<SmimeError>) {
    let mut certificate_emails = Vec::new();
    let mut certificate_names = Vec::new();
    let mut other_notes = Vec::new();

    for rdn in cert.subject().clone() {
        for attr in rdn {
            match attr.type_id {
                COMMON_NAME_OID => {
                    let cn_value = match &attr.value {
                        cryptography_x509::common::AttributeValue::PrintableString(s) => Some(s.as_str().to_string()),
                        cryptography_x509::common::AttributeValue::AnyString(tlv) => {
                            if tlv.tag() == asn1::Tag::primitive(12) {
                                if let Ok(s) = str::from_utf8(tlv.data()) { Some(s.to_string()) } else { None }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some(cn) = cn_value {
                        if cn.contains('@') {
                            certificate_emails.push(email_domain_to_a_label(&cn));
                        } else {
                            certificate_names.push(cn);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Ok(extensions) = cert.extensions() {
        if let Some(ext) = extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
            if let Ok(sans) = ext.value::<SubjectAlternativeName>() {
                for san in sans {
                    match san {
                        GeneralName::RFC822Name(email) => {
                            // RFC 9598 §4: domains MUST conform to IDNA2008. We don't
                            // validate this - if a CA has already signed the cert, the
                            // domain is accepted as-is. The idna crate handles A-label
                            // conversion during matching in email_domain_to_a_label().
                            certificate_emails.push(email.0.to_string());
                        }
                        GeneralName::DNSName(dns) => {
                            certificate_emails.push(dns.0.to_string());
                        }
                        GeneralName::UniformResourceIdentifier(uri) => {
                            certificate_emails.push(uri.0.to_string());
                        }
                        GeneralName::IPAddress(ip) => {
                            let formatted = match ip.len() {
                                4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                                16 => {
                                    let segs: Vec<String> =
                                        (0..8).map(|i| format!("{:x}", u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]]))).collect();
                                    segs.join(":")
                                }
                                _ => hex::encode(ip),
                            };
                            certificate_emails.push(formatted);
                        }
                        GeneralName::OtherName(other) => {
                            // RFC 9598 §3: SmtpUTF8Mailbox for internationalized email addresses.
                            // ASCII-only Local-parts SHOULD use rfc822Name instead, but we
                            // intentionally don't reject SmtpUTF8Mailbox with ASCII-only Local-part
                            // as this is an issuance requirement, not a verification concern.
                            if other.type_id == ID_ON_SMTP_UTF8_MAILBOX_OID {
                                // RFC 8398 §3: SmtpUTF8Mailbox value MUST be a UTF8String (tag 0x0C)
                                if other.value.tag() != asn1::Tag::primitive(0x0C) {
                                    other_notes.push(SmimeError::OtherNameParseError {
                                        err: format!("SmtpUTF8Mailbox must be UTF8String, got tag {:?}", other.value.tag()),
                                        hex_data: hex::encode(other.value.data()),
                                    });
                                    continue;
                                }
                                let raw = other.value.data();
                                // RFC 8398 §3: MUST NOT issue certificates with empty SmtpUTF8Mailbox
                                if raw.is_empty() {
                                    other_notes.push(SmimeError::OtherNameParseError {
                                        err: "SmtpUTF8Mailbox must not be empty".to_string(),
                                        hex_data: String::new(),
                                    });
                                    continue;
                                }
                                // RFC 9598 §3: MUST NOT contain a UTF-8 BOM
                                if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
                                    other_notes.push(SmimeError::OtherNameParseError {
                                        err: "SmtpUTF8Mailbox contains a UTF-8 BOM (RFC 9598 \u{00a7}3 violation)".to_string(),
                                        hex_data: hex::encode(&raw[..3]),
                                    });
                                }
                                match std::str::from_utf8(raw) {
                                    Ok(email) => {
                                        let email = email.trim_start_matches('\u{FEFF}');
                                        certificate_emails.push(email.to_string());
                                    }
                                    Err(e) => {
                                        other_notes
                                            .push(SmimeError::OtherNameParseError { err: e.to_string(), hex_data: hex::encode(raw) });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // 7.1.2.3.a: certificatePolicies (SHALL be present)
        if let Some(ext) = extensions.get_extension(&CERTIFICATE_POLICIES_OID) {
            if let Ok(policies) = ext.value::<asn1::SequenceOf<PolicyInformation<Asn1Read>>>() {
                let mut smime_br_policy_count = 0;

                for policy in policies {
                    if SMIME_BR_OIDS.contains(&policy.policy_identifier) {
                        smime_br_policy_count += 1;
                    }

                    // Policy Qualifiers: The presence or format of id-qt-cps (CPS URL) or id-qt-unotice qualifiers
                    if let Some(qualifiers) = policy.policy_qualifiers {
                        for qualifier in qualifiers {
                            if qualifier.policy_qualifier_id == CP_CPS_URI_OID {
                                match qualifier.qualifier {
                                    Qualifier::CpsUri(_) => {
                                        // Valid CPS URL format
                                    }
                                    _ => {
                                        other_notes.push(SmimeError::CertPolicyWarning {
                                            detail: "CPS qualifier must use id-qt-cps format".into(),
                                        });
                                        // TODO: Should this be fatal?
                                    }
                                }
                            } else if qualifier.policy_qualifier_id == CP_USER_NOTICE_OID {
                                match qualifier.qualifier {
                                    Qualifier::UserNotice(_) => {
                                        // Valid User Notice format
                                    }
                                    _ => {
                                        other_notes.push(SmimeError::CertPolicyWarning {
                                            detail: "User Notice qualifier must use id-qt-unotice format".into(),
                                        });
                                        // TODO: Should this be fatal?
                                    }
                                }
                            }
                        }
                    }
                }

                if smime_br_policy_count == 0 {
                    // According to Section 7.1.6.4, a Subscriber Certificate SHALL contain a policy identifier from 7.1.6.1.
                    // Section 7.1.2.3.a says it SHALL include exactly one of the reserved policyIdentifiers.
                } else if smime_br_policy_count > 1 {
                    other_notes.push(SmimeError::CertPolicyWarning {
                        detail: "certificatePolicies should include exactly one reserved policyIdentifier".into(),
                    });
                    // TODO: Should this be fatal?
                }
            }
        }
    }

    (certificate_emails, certificate_names, other_notes)
}

fn extract_rfc9788_info(content_type: &mail_parser::ContentType<'_>) -> (bool, Option<String>) {
    // RFC 9788: 2.1.1 Content-Type Parameter: hp
    if let Some(hp) = content_type.attribute("hp") {
        // hp must be set to "clear" or "cipher"
        if hp.eq_ignore_ascii_case("clear") || hp.eq_ignore_ascii_case("cipher") {
            return (true, Some(hp.to_string()));
        }
    }
    // NOTE: RFC 9788: 2.2. HP-Outer Header Field is not relevant for signed-only messages
    // NOTE: RFC 9788 §10.2: hp="cipher" on signed-only messages is common in practice;
    // the from_address replacement already handles the trust boundary correctly.
    // NOTE: RFC 9788 §4.10: RFC8551HP backward compatibility is intentionally not supported.
    (false, None)
}

/// Tracks the resolved sender identity across multiple signers.
///
/// Per RFC 5751 Section 3.1, the signing certificate's email address should match
/// the sender. When the inner (signed) From matches the certificate, we prefer it
/// over the outer (potentially unsigned) From header.
///
/// The resolver accumulates matches across signers: a later signer that provides
/// both address+comment will upgrade an earlier address-only match.
#[derive(Debug, Clone, Default)]
pub struct SenderResolver {
    pub from_address: Option<String>,
    pub from_comment: Option<String>,
    sender_matched: bool,
    comment_matched: bool,
}

impl SenderResolver {
    /// Try to resolve the sender from the inner message's From header and the
    /// signer certificate's identities (SAN emails and CN names).
    pub fn update(
        &mut self,
        inner_from_address: Option<&str>,
        inner_from_name: Option<&str>,
        certificate_emails: &[String],
        certificate_names: &[String],
    ) -> (bool, Vec<SmimeError>) {
        let mut warnings = Vec::new();
        let inner_addr = match inner_from_address {
            Some(a) => a,
            None => return (false, warnings),
        };

        let normalized = email_domain_to_a_label(inner_addr);
        let address_matches = certificate_emails.iter().any(|san| email_domain_to_a_label(san).eq_ignore_ascii_case(&normalized));

        if !address_matches || (self.sender_matched && self.comment_matched) {
            return (false, warnings);
        }

        // RFC 9598 §5: Local-part MUST NOT be case-folded. We still match
        // case-insensitively (most providers are case-insensitive), but warn
        // when the local-parts differ in case.
        if let Some((from_local, _)) = inner_addr.split_once('@') {
            for san in certificate_emails {
                let san_normalized = email_domain_to_a_label(san);
                if san_normalized.eq_ignore_ascii_case(&normalized) {
                    if let Some((cert_local, _)) = san_normalized.split_once('@') {
                        if from_local != cert_local && from_local.eq_ignore_ascii_case(cert_local) {
                            warnings.push(SmimeError::LocalPartCaseMismatch { from: inner_addr.to_string(), cert: san.clone() });
                        }
                    }
                    break;
                }
            }
        }

        let comment_matches = match inner_from_name {
            Some(name) => certificate_names.iter().any(|cn| cn.eq_ignore_ascii_case(name)),
            None => false,
        };

        self.from_address = inner_from_address.map(|a| a.to_string());
        self.from_comment = match comment_matches {
            true => inner_from_name.map(|n| n.to_string()),
            false => None,
        };
        self.sender_matched = true;
        self.comment_matched = comment_matches;
        (true, warnings)
    }
}

fn check_date_mismatch(date_a: Option<DateTime<Utc>>, date_b: Option<DateTime<Utc>>, msg: &str) -> Option<SmimeError> {
    let (a, b) = match (date_a, date_b) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };
    let delta = a - b;
    if delta > Duration::hours(1) || delta < Duration::hours(-1) {
        return Some(SmimeError::DateMismatch { msg: msg.to_string(), date_a: a.to_rfc3339(), date_b: b.to_rfc3339() });
    }
    None
}

/// Ensure CRLF before each MIME boundary and a trailing CRLF.
/// Works around a WildDuck bug where boundaries lack preceding CRLF.
fn normalize_wildduck_content(content: &[u8], inner_message: &mail_parser::Message<'_>) -> Vec<u8> {
    let mut boundary = None;
    if let Some(ct) = inner_message.content_type() {
        for attr in ct.attributes.as_deref().unwrap_or(&[]) {
            if attr.name.to_lowercase() == "boundary" {
                boundary = Some(format!("\r\n--{}", attr.value));
                break;
            }
        }
    }

    let mut out = Vec::with_capacity(content.len() + 32);
    let mut i = 0;
    while i < content.len() {
        if let Some(ref b) = boundary {
            if content[i..].starts_with(b.as_bytes()) {
                let preceded_by_crlf = i >= 2 && &content[i - 2..i] == b"\r\n";
                if !preceded_by_crlf {
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        out.push(content[i]);
        i += 1;
    }

    if !content.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn parse_signed_data(der: &[u8], is_detached: bool) -> Result<cryptography_x509::pkcs7::SignedData<'_>, SmimeError> {
    let content_info = asn1::parse_single::<ContentInfo>(der).map_err(|e| {
        if is_detached { SmimeError::ParsePkcs7Sig { err: e.to_string() } } else { SmimeError::ParsePkcs7Msg { err: e.to_string() } }
    })?;
    match content_info.content {
        Content::SignedData(sd) => Ok(*sd.into_inner()),
        _ => Err(SmimeError::NoPkcs7Content),
    }
}

/// S/MIME shape of a MIME part, derived from its content type
#[derive(PartialEq, Eq)]
pub(crate) enum SmimeContentKind {
    /// application/(x-)pkcs7-mime: opaque/enveloped CMS.
    Pkcs7Mime,
    /// application/(x-)pkcs7-signature: detached signature part.
    Pkcs7Signature,
    /// multipart/signed with an (x-)pkcs7-signature protocol: clear-signed container.
    SignedMultipart,
    Other,
}

pub(crate) fn smime_content_kind(ct: &mail_parser::ContentType<'_>) -> SmimeContentKind {
    let subtype_is = |name: &str| ct.c_subtype.as_ref().is_some_and(|s| s.eq_ignore_ascii_case(name));
    if ct.c_type.as_ref().eq_ignore_ascii_case("application") {
        if subtype_is("pkcs7-mime") || subtype_is("x-pkcs7-mime") {
            return SmimeContentKind::Pkcs7Mime;
        }
        if subtype_is("pkcs7-signature") || subtype_is("x-pkcs7-signature") {
            return SmimeContentKind::Pkcs7Signature;
        }
    }
    let is_pkcs7_protocol = ct
        .attribute("protocol")
        .is_some_and(|p| p.eq_ignore_ascii_case("application/pkcs7-signature") || p.eq_ignore_ascii_case("application/x-pkcs7-signature"));
    if ct.c_type.as_ref().eq_ignore_ascii_case("multipart") && subtype_is("signed") && is_pkcs7_protocol {
        return SmimeContentKind::SignedMultipart;
    }
    SmimeContentKind::Other
}

fn extract_smime_clear_signed_content(
    message: &mail_parser::Message<'_>,
    eml_content: &[u8],
    boundary: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), SmimeError> {
    let parts = &message.parts;
    if parts.len() < 2 {
        return Err(SmimeError::MsgNotEnoughParts);
    }

    let signature_part =
        parts.iter().find(|part| part.content_type().is_some_and(|ct| smime_content_kind(ct) == SmimeContentKind::Pkcs7Signature));

    let signature_part = signature_part.ok_or(SmimeError::NoSigSubpart)?;

    let signature_p7s_raw = signature_part.contents();
    let p7s_der = ber_to_der_cms(signature_p7s_raw).map_err(|e| SmimeError::ParsePkcs7Sig { err: format!("BER-to-DER: {}", e) })?;

    let content = extract_first_multipart_part_raw(eml_content, boundary.ok_or(SmimeError::MissingBoundary)?)
        .map_err(|e| SmimeError::ExtractMultipart { err: e.to_string() })?
        .to_vec();

    Ok((content, p7s_der))
}

pub(crate) fn extract_smime_opaque_p7m_der(message: &mail_parser::Message<'_>) -> Result<Vec<u8>, SmimeError> {
    let p7m_contents = message
        .parts
        .iter()
        .find(|part| part.content_type().is_some_and(|ct| smime_content_kind(ct) == SmimeContentKind::Pkcs7Mime))
        .map(|part| part.contents())
        .ok_or(SmimeError::NoPkcs7Mime)?;

    ber_to_der_cms(p7m_contents).map_err(|e| SmimeError::ParsePkcs7Msg { err: format!("BER-to-DER: {}", e) })
}

pub fn hash_oid_to_hash_type_permitted(oid: &ObjectIdentifier) -> Result<HashType, SmimeError> {
    match hash_oid_to_hash_type(oid.clone()) {
        Ok(h)
            if matches!(
                h,
                HashType::SHA256
                    | HashType::SHA384
                    | HashType::SHA512
                    | HashType::SHA3_256
                    | HashType::SHA3_384
                    | HashType::SHA3_512
                    | HashType::SHAKE128
                    | HashType::SHAKE256
            ) =>
        {
            Ok(h)
        }
        Ok(h) => Err(SmimeError::DisallowedDigestAlg { alg: format!("{:?}", h), idx: 0 }),
        _ => Err(SmimeError::UnsupportedDigestAlg { alg: format!("{:?}", oid), idx: 0 }),
    }
}

fn check_algorithms(signer: &SignerInfo<'_>, idx: usize) -> Result<Vec<SmimeError>, SmimeError> {
    let mut warnings = Vec::new();
    let digest_oid = signer.digest_algorithm.oid();
    let hash_type = hash_oid_to_hash_type_permitted(digest_oid).map_err(|e| match e {
        SmimeError::DisallowedDigestAlg { alg, .. } => SmimeError::DisallowedDigestAlg { alg, idx },
        SmimeError::UnsupportedDigestAlg { alg, .. } => SmimeError::UnsupportedDigestAlg { alg, idx },
        _ => e,
    })?;

    if *signer.digest_encryption_algorithm.oid() == RSA_OID {
        return Ok(warnings);
    }

    if !SMIME_PERMITTED_SIGNATURE_ALGORITHMS.contains(&signer.digest_encryption_algorithm) {
        return Err(SmimeError::DisallowedSignatureAlg { alg: format!("{:?}", signer.digest_encryption_algorithm.oid()), idx });
    }

    let sig_params = identify_signature_algorithm_parameters(&signer.digest_encryption_algorithm)
        .map_err(|_| SmimeError::UnsupportedSignatureAlg { alg: format!("{:?}", signer.digest_encryption_algorithm.oid()), idx })?;

    // NOTE:
    // If DigestAlgorithmIdentifier and SignatureAlgorithmIdentifier disagree, use the one specified by SignatureAlgorithmIdentifier
    // If SignatureAlgorithmIdentifier does not specify a digest, use DigestAlgorithmIdentifier
    // In any case, this mismatch will currently result in a warning
    //
    // PQ CMS has a placeholder DigestAlgorithmIdentifier to avoid things rejecting new digest algorithms and specify the actual hash in SignatureAlgorithmIdentifier
    //
    // More discussion: https://github.com/openssl/openssl/issues/11413
    if let SignatureParameters::RSAPKCS1v15 { ref hash }
    | SignatureParameters::RSAPSS { ref hash }
    | SignatureParameters::ECDSA { ref hash } = sig_params
    {
        if *hash != HashType::None && *hash != hash_type {
            warnings.push(SmimeError::DigestAlgorithmWarning {
                detail: format!("digest algorithm '{:?}' mismatches signature hash algorithm '{:?}'", hash_type, hash),
                idx,
            });
        }
    }

    // RFC 4056 §2.1: RSA-PSS MGF1 hash should match hashAlgorithm; trailerField must be 1
    if let cryptography_x509::common::AlgorithmParameters::RsaPss(Some(ref pss)) = signer.digest_encryption_algorithm.params {
        let hash_oid = pss.hash_algorithm.oid();
        let mgf_oid = pss.mask_gen_algorithm.params.oid();
        if hash_oid != mgf_oid {
            warnings.push(SmimeError::RsaPssParameterWarning {
                detail: format!("MGF1 hash '{}' differs from hashAlgorithm '{}'", mgf_oid, hash_oid),
                idx,
            });
        }
        if let Some(trailer) = pss.trailer_field {
            if trailer != 1 {
                warnings.push(SmimeError::RsaPssParameterWarning {
                    detail: format!("trailerField has unexpected value {} (expected 1)", trailer),
                    idx,
                });
            }
        }
    }

    // RFC 9882 Section 3.3, Table 1: Check digest algorithm strength for ML-DSA
    let sig_oid = signer.digest_encryption_algorithm.oid();
    let min_hashes: Option<&[HashType]> = if *sig_oid == ML_DSA_44_OID {
        // ML-DSA-44 (NIST Level 2): SHA-256+, SHA3-256+, SHAKE128, SHAKE256
        Some(&[
            HashType::SHA256,
            HashType::SHA384,
            HashType::SHA512,
            HashType::SHA3_256,
            HashType::SHA3_384,
            HashType::SHA3_512,
            HashType::SHAKE128,
            HashType::SHAKE256,
        ])
    } else if *sig_oid == ML_DSA_65_OID {
        // ML-DSA-65 (NIST Level 3): SHA-384+, SHA3-384+, SHAKE256
        Some(&[HashType::SHA384, HashType::SHA512, HashType::SHA3_384, HashType::SHA3_512, HashType::SHAKE256])
    } else if *sig_oid == ML_DSA_87_OID {
        // ML-DSA-87 (NIST Level 5): SHA-512, SHA3-512, SHAKE256
        Some(&[HashType::SHA512, HashType::SHA3_512, HashType::SHAKE256])
    } else {
        None
    };

    if let Some(allowed) = min_hashes {
        if !allowed.contains(&hash_type) {
            warnings.push(SmimeError::DigestAlgorithmWarning {
                detail: format!("digest algorithm '{:?}' is weaker than recommended for signature algorithm '{:?}'", hash_type, sig_oid),
                idx,
            });
        }
    }

    Ok(warnings)
}

fn build_policy_builder(ca_certs: &'_ [OwnedCertificate]) -> Result<PolicyBuilder<'_>, SmimeError> {
    let mut py_ca_certs: Vec<Certificate<'_>> = Vec::new();
    for owned in ca_certs {
        py_ca_certs.push(owned.borrow_dependent().clone());
    }
    let store = PyStore::new(py_ca_certs).map_err(|e| SmimeError::PolicySetup { step: "create CA storage".into(), err: e.to_string() })?;

    PolicyBuilder::new()
        .store(store)
        .map_err(|e| SmimeError::PolicySetup { step: "create policy".into(), err: e.to_string() })?
        .max_chain_depth(4)
        .map_err(|e| SmimeError::PolicySetup { step: "set max chain depth".into(), err: e.to_string() })?
        .time(cryptography_x509_verify::now_asn1())
        .map_err(|e| SmimeError::PolicySetup { step: "set verification time".into(), err: e.to_string() })
}

pub fn verify_smime_from_eml_detailed(eml_text: String, trust: TrustConfig) -> SmimeValidationResult {
    let trust_stores = trust.stores;
    let ca_file_pem = trust.ca_file_pem.as_deref();

    let mut result = SmimeValidationResult {
        signing_system: SigningSystem::Other,
        signers: Vec::new(),
        failures: Vec::new(),
        signed_content: None,
        from_address: None,
        from_comment: None,
        date: None,
        encryption_info: None,
    };

    let eml_content = eml_text.as_bytes();

    let message = match MessageParser::default().parse(eml_content) {
        Some(msg) => msg,
        None => {
            console_log!("Error parsing .eml string as MIME message");
            result.failures.push(SmimeError::ParseEml);
            return result;
        }
    };

    console_log!("Parsed MIME message successfully");

    let content_type = match message.content_type() {
        Some(ct) => ct,
        None => {
            result.failures.push(SmimeError::MissingContentType);
            return result;
        }
    };
    console_log!("content_type: {:?}", content_type);

    let is_multipart = content_type.c_type.as_ref().eq_ignore_ascii_case("multipart");
    let boundary: Option<String> = content_type.attribute("boundary").map(|b| b.to_string());

    if is_multipart && boundary.is_none() {
        result.failures.push(SmimeError::MissingBoundary);
        return result;
    }

    let outer_from = message.from().and_then(|address| address.first().cloned());
    let outer_date = message.date().and_then(mail_parser_date_to_chrono);

    match smime_content_kind(content_type) {
        SmimeContentKind::SignedMultipart => {
            result.signing_system = SigningSystem::MultipartSignedSMIME;
            let (detached_content, p7s_der) = match extract_smime_clear_signed_content(&message, eml_content, boundary.as_deref()) {
                Ok(res) => res,
                Err(e) => {
                    result.failures.push(e);
                    return result;
                }
            };
            let signed_data = match parse_signed_data(&p7s_der, true) {
                Ok(sd) => sd,
                Err(e) => {
                    result.failures.push(e);
                    return result;
                }
            };
            verify_signed_data(
                &signed_data,
                SignedTarget::Detached(&detached_content),
                &trust_stores,
                ca_file_pem,
                outer_from.as_ref(),
                outer_date,
                &mut result,
            );
        }
        SmimeContentKind::Pkcs7Mime => {
            result.signing_system = SigningSystem::MIMEPartSMIME;
            let p7m_der = match extract_smime_opaque_p7m_der(&message) {
                Ok(der) => der,
                Err(e) => {
                    result.failures.push(e);
                    return result;
                }
            };
            let signed_data = match parse_signed_data(&p7m_der, false) {
                Ok(sd) => sd,
                Err(e) => {
                    result.failures.push(e);
                    return result;
                }
            };
            match SignedTarget::econtent(&signed_data) {
                Ok(target) => {
                    verify_signed_data(&signed_data, target, &trust_stores, ca_file_pem, outer_from.as_ref(), outer_date, &mut result)
                }
                Err(e) => result.failures.push(e),
            }
        }
        _ => result.failures.push(SmimeError::NoSmimeSig),
    }
    result
}

/// Validates a signer's attributes and finds matching certificates.
/// Returns `None` (and pushes failures) if the signer should be skipped.
fn prepare_signer<'a>(
    signer: &SignerInfo<'_>,
    certs: &'a [Certificate<'a>],
    idx: usize,
    result: &mut SmimeValidationResult,
) -> Option<(Option<DateTime<Utc>>, Vec<&'a Certificate<'a>>)> {
    use crate::cryptography_x509::pkcs7::SignerIdentifier;

    let sid_str = match &signer.issuer_and_serial_number {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            format!("{} ({:?})", policy::extension::dn_to_string(ias.issuer.unwrap_read()), ias.serial_number)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => format!("SKI: {}", hex::encode(ski)),
    };
    console_log!("Signer: {}, CMS version: {}", sid_str, signer.version);

    // RFC 5652 §5.3: SignerInfo version must match identifier type
    let expected_version: u8 = match &signer.issuer_and_serial_number {
        SignerIdentifier::IssuerAndSerialNumber(_) => 1,
        SignerIdentifier::SubjectKeyIdentifier(_) => 3,
    };
    if signer.version != expected_version {
        result.failures.push(SmimeError::CmsVersionMismatch {
            structure: "SignerInfo".into(),
            expected: expected_version,
            actual: signer.version,
            idx: Some(idx),
        });
    }

    match check_algorithms(signer, idx) {
        Ok(w) => result.failures.extend(w),
        Err(e) => {
            result.failures.push(e);
            return None;
        }
    }

    let mut signing_time = None;
    let mut has_content_type_attr = false;
    let mut smime_capabilities_count = 0u32;
    let mut signing_time_count = 0u32;

    if let Some(attrs) = signer.authenticated_attributes.as_ref() {
        for attr in attrs.unwrap_read().clone() {
            match attr.type_id {
                CONTENT_TYPE_OID => {
                    has_content_type_attr = true;
                    let values = attr.values.unwrap_read().clone().collect::<Vec<_>>();
                    if values.len() == 1 {
                        if let Ok(oid) = asn1::parse_single::<asn1::ObjectIdentifier>(values[0].full_data()) {
                            if oid != PKCS7_DATA_OID {
                                result.failures.push(SmimeError::ContentTypeMismatch { idx });
                            }
                        }
                    }
                }
                SIGNING_TIME_OID => {
                    signing_time_count += 1;
                    let mut values = attr.values.unwrap_read().clone().collect::<Vec<_>>();
                    if values.len() == 1 {
                        if let Ok(time) = asn1::parse_single::<Time>(values.remove(0).full_data()) {
                            signing_time = asn1_time_to_chrono(&time);
                        }
                    }
                }
                CMS_ALGORITHM_PROTECTION_OID => {
                    let mut values = attr.values.unwrap_read().clone().collect::<Vec<_>>();
                    if values.len() == 1 {
                        if let Ok(prot) = asn1::parse_single::<CmsAlgorithmProtection>(values.remove(0).full_data()) {
                            if prot.digest_algorithm != signer.digest_algorithm {
                                result.failures.push(SmimeError::AlgorithmProtectionMismatch { field: "digestAlgorithm".to_string(), idx });
                            }
                            if let Some(ref sig_alg) = prot.signature_algorithm {
                                if *sig_alg != signer.digest_encryption_algorithm {
                                    result
                                        .failures
                                        .push(SmimeError::AlgorithmProtectionMismatch { field: "signatureAlgorithm".to_string(), idx });
                                }
                            }
                        }
                    }
                }
                SMIME_CAPABILITIES_OID => {
                    smime_capabilities_count += 1;
                }
                SIGNING_CERTIFICATE_OID | SIGNING_CERTIFICATE_V2_OID => {}
                _ => {}
            }
        }
    }

    // RFC 5652 §11.1: content-type attribute MUST be present when signed attributes exist
    if signer.authenticated_attributes.is_some() && !has_content_type_attr {
        result.failures.push(SmimeError::MissingContentTypeAttr { idx });
    }
    // RFC 8551 §2.5.2: SMIMECapabilities cardinality violation
    if smime_capabilities_count > 1 {
        result.failures.push(SmimeError::AttributeCardinality { attr: "SMIMECapabilities".into(), idx });
    }
    // RFC 5652 §11.3: at most one signing-time attribute
    if signing_time_count > 1 {
        result.failures.push(SmimeError::AttributeCardinality { attr: "signing-time".into(), idx });
    }

    let candidates: Vec<&Certificate> = certs
        .iter()
        .filter(|cert| match &signer.issuer_and_serial_number {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                cert.issuer() == ias.issuer.unwrap_read() && cert.tbs_cert.serial == ias.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                if let Ok(extensions) = cert.extensions() {
                    if let Some(ext) = extensions.get_extension(&SUBJECT_KEY_IDENTIFIER_OID) {
                        if let Ok(cert_ski) = ext.value::<&[u8]>() {
                            return cert_ski == *ski;
                        }
                    }
                }
                false
            }
        })
        .collect();

    if candidates.is_empty() {
        result.failures.push(SmimeError::SignerCertNotFound { id: sid_str });
        return None;
    }

    Some((signing_time, candidates))
}

fn validate_chain(
    signer_leaf: &Certificate<'_>,
    certs: &[Certificate<'_>],
    verifier: &cryptography_x509_verify::PyEmailVerifier<'_>,
    idx: usize,
) -> (Vec<String>, bool, Vec<SmimeError>) {
    let fp = sha256_fingerprint_hex(signer_leaf).unwrap_or_else(|| "<encoding error>".to_string());
    let intermediaries: Vec<Certificate<'_>> = certs.iter().filter(|c| *c != signer_leaf && c.issuer() != c.subject()).cloned().collect();
    if !intermediaries.is_empty() {
        console_log!("Amount of found intermediaries: {:?}", intermediaries.len());
        for intermediary in &intermediaries {
            console_log!("Intermediary: {:?}", policy::extension::dn_to_string(intermediary.subject()));
        }
    }

    match verifier.verify(signer_leaf.clone(), intermediaries) {
        Ok(verified) => {
            let chain = verified
                .chain
                .iter()
                .filter_map(|c| {
                    let c = c.borrow_dependent();
                    certs
                        .iter()
                        .find(|p7| p7.issuer() == c.issuer() && p7.tbs_cert.serial == c.tbs_cert.serial)
                        .and_then(|p7| sha256_fingerprint_hex(p7))
                })
                .collect();
            (chain, true, Vec::new())
        }
        Err(e) => (Vec::new(), false, vec![SmimeError::ChainValidation { fp, idx, err: e.to_string() }]),
    }
}

fn build_signer_entry(
    signer_leaf: &Certificate<'_>,
    signer: &SignerInfo<'_>,
    signing_time: Option<DateTime<Utc>>,
    mut checks: SignatureChecks,
    trust_store_label: &str,
    outer_date: Option<DateTime<Utc>>,
) -> SignerValidation {
    let (emails, names, notes) = extract_cert_info(signer_leaf);
    checks.certificate_emails.extend(emails);
    checks.certificate_names.extend(names);
    checks.other_notes.extend(notes);

    let mut entry = SignerValidation {
        signature_valid: false,
        chain: Vec::new(),
        validation_details: ValidationDetails {
            trust_store_used: trust_store_label.to_string(),
            certificate_trusted_valid: false,
            certificate: match asn1::write_single(signer_leaf) {
                Ok(der) => pem::encode(&Pem::new("CERTIFICATE", der)).replace("\r\n", "\n"),
                Err(_) => String::new(),
            },
            revocation_status: None,
            scts_valid: None,
            other_notes: Vec::new(),
            checks,
        },
        signing_time,
    };

    // TODO: verify countersignatures and timestamp tokens
    if let Some(unauth) = signer.unauthenticated_attributes.as_ref() {
        for attr in unauth.unwrap_read().clone() {
            match attr.type_id {
                TIMESTAMP_TOKEN_OID => {
                    console_log!("unauthenticated_attr: timestamp token present");
                }
                COUNTERSIGNATURE_OID => {
                    console_log!("unauthenticated_attr: countersignature present");
                }
                _ => {}
            }
        }
    }

    if let Some(note) = check_date_mismatch(
        entry.signing_time,
        outer_date,
        "The time difference between the signing time and outer date header is larger than one hour",
    ) {
        entry.validation_details.other_notes.push(note);
    }

    entry
}

/// If the signer is valid, resolve the sender identity and check date consistency.
fn resolve_sender(
    entry: &mut SignerValidation,
    inner_from_addr: Option<&mail_parser::Addr<'_>>,
    inner_date: Option<DateTime<Utc>>,
    outer_date: Option<DateTime<Utc>>,
    sender_resolver: &mut SenderResolver,
    result: &mut SmimeValidationResult,
) {
    if !entry.signature_valid {
        return;
    }
    if let Some(inner_from) = inner_from_addr {
        let (updated, warnings) = sender_resolver.update(
            inner_from.address.as_deref(),
            inner_from.name.as_deref(),
            &entry.validation_details.checks.certificate_emails,
            &entry.validation_details.checks.certificate_names,
        );
        entry.validation_details.other_notes.extend(warnings);
        if updated {
            result.from_address = sender_resolver.from_address.clone();
            result.from_comment = sender_resolver.from_comment.clone();
            result.date = inner_date;
        }
    }
    if let Some(note) =
        check_date_mismatch(outer_date, inner_date, "The time difference between the outer date and the inner date is larger than one hour")
    {
        entry.validation_details.other_notes.push(note);
    }
}

/// RFC 5652 §5.1: validate SignedData version
fn validate_signed_data_version(signed_data: &cryptography_x509::pkcs7::SignedData<'_>, signers: &[SignerInfo<'_>]) -> Option<SmimeError> {
    let has_v2_attr_cert = signed_data
        .certificates
        .as_ref()
        .is_some_and(|cs| cs.unwrap_read().clone().any(|c| matches!(c, cryptography_x509::pkcs7::CertificateChoices::V2AttrCert(_))));
    let has_v1_attr_cert = signed_data
        .certificates
        .as_ref()
        .is_some_and(|cs| cs.unwrap_read().clone().any(|c| matches!(c, cryptography_x509::pkcs7::CertificateChoices::V1AttrCert(_))));
    let has_other_cert = signed_data
        .certificates
        .as_ref()
        .is_some_and(|cs| cs.unwrap_read().clone().any(|c| matches!(c, cryptography_x509::pkcs7::CertificateChoices::OtherCertificate(_))));
    let has_other_crl = signed_data
        .crls
        .as_ref()
        .is_some_and(|crls| crls.unwrap_read().clone().any(|c| matches!(c, cryptography_x509::pkcs7::RevocationInfoChoice::Other(_))));
    let has_ski_signer =
        signers.iter().any(|s| matches!(s.issuer_and_serial_number, cryptography_x509::pkcs7::SignerIdentifier::SubjectKeyIdentifier(_)));
    let expected: u8 = if has_other_cert || has_other_crl {
        5
    } else if has_v2_attr_cert {
        4
    } else if has_v1_attr_cert || has_ski_signer || !matches!(signed_data.content_info.content, Content::Data(_)) {
        3
    } else {
        1
    };
    if signed_data.version != expected {
        Some(SmimeError::CmsVersionMismatch { structure: "SignedData".into(), expected, actual: signed_data.version, idx: None })
    } else {
        None
    }
}

fn extract_certificates<'a>(signed_data: &'a cryptography_x509::pkcs7::SignedData<'a>) -> Vec<Certificate<'a>> {
    signed_data
        .certificates
        .as_ref()
        .map(|c| {
            c.unwrap_read()
                .clone()
                .filter_map(
                    |choice| {
                        if let cryptography_x509::pkcs7::CertificateChoices::Certificate(cert) = choice { Some(cert) } else { None }
                    },
                )
                .collect()
        })
        .unwrap_or_default()
}

/// Shared setup for signed data verification. Pushes errors to `result` on failure.
fn prepare_signed_data_verification<'a>(
    signed_data: &'a cryptography_x509::pkcs7::SignedData<'a>,
    content_for_display: &'a [u8],
    trust_stores: &[TrustStore],
    ca_file_pem: Option<&[u8]>,
    outer_from: Option<&mail_parser::Addr<'_>>,
    outer_date: Option<DateTime<Utc>>,
    result: &mut SmimeValidationResult,
) -> Option<(Vec<Certificate<'a>>, Vec<SignerInfo<'a>>, Vec<OwnedCertificate>, mail_parser::Message<'a>)> {
    if !matches!(signed_data.content_info.content, Content::Data(_)) {
        result.failures.push(SmimeError::UnexpectedEContentType);
        return None;
    }

    let certs = extract_certificates(signed_data);
    let signers = signed_data.signer_infos.unwrap_read().clone().collect::<Vec<_>>();

    if let Some(err) = validate_signed_data_version(signed_data, &signers) {
        result.failures.push(err);
    }

    result.signed_content = Some(content_for_display.to_vec());

    let ca_certs = match load_ca_certs(trust_stores, ca_file_pem) {
        Ok(certs) => certs,
        Err(e) => {
            result.failures.push(e);
            return None;
        }
    };

    let outer_from = match outer_from {
        Some(address) => address,
        None => return None,
    };
    result.from_address = outer_from.address.as_ref().map(|addr| email_domain_to_a_label(addr));
    result.from_comment = outer_from.name.as_ref().map(|n| n.to_string());
    result.date = outer_date;

    let inner_message = match MessageParser::default().parse(content_for_display) {
        Some(message) => message,
        None => {
            result.failures.push(SmimeError::ParseInner);
            return None;
        }
    };

    Some((certs, signers, ca_certs, inner_message))
}

/// What a SignedData's signatures cover
#[derive(Clone, Copy)]
pub(crate) enum SignedTarget<'a> {
    /// signature over external content; signedAttrs REQUIRED
    Detached(&'a [u8]),
    /// signatures cover the encapsulated eContent.
    EContent(&'a [u8]),
}

impl<'a> SignedTarget<'a> {
    fn content(&self) -> &'a [u8] {
        match *self {
            SignedTarget::Detached(c) | SignedTarget::EContent(c) => c,
        }
    }

    fn econtent(signed_data: &'a cryptography_x509::pkcs7::SignedData<'a>) -> Result<Self, SmimeError> {
        match &signed_data.content_info.content {
            Content::Data(Some(data)) => Ok(SignedTarget::EContent(data.as_inner())),
            _ => Err(SmimeError::NoPkcs7Content),
        }
    }

    /// Key-independent guard, checked once per signer; `Some` rejects the signer.
    fn precheck_signer(&self, has_signed_attrs: bool) -> Option<SmimeError> {
        match *self {
            SignedTarget::Detached(_) if !has_signed_attrs => {
                Some(SmimeError::SigVerify { err: "detached signature requires signedAttrs".to_string() })
            }
            // draft-ietf-lamps-cms-euf-cma-signeddata §5.1: eContent without signedAttrs must not be a SignedAttributes
            SignedTarget::EContent(content) if !has_signed_attrs && econtent_looks_like_signed_attrs(content) => {
                Some(SmimeError::SigVerify {
                    err: "eContent without signedAttrs is a DER-encoded SignedAttributes (possible EUF-CMA forgery)".to_string(),
                })
            }
            _ => None,
        }
    }

    /// Verify one candidate key: sets `checks`, pushes failures, returns `true` if it verifies.
    fn verify_candidate(
        &self,
        pk: &AnyPublicKey,
        signer: &SignerInfo<'_>,
        has_signed_attrs: bool,
        inner_message: &mail_parser::Message<'_>,
        checks: &mut SignatureChecks,
        result: &mut SmimeValidationResult,
    ) -> bool {
        match *self {
            SignedTarget::Detached(content) => {
                // signedAttrs guaranteed present by precheck_signer.
                let mut deferred_failures: Vec<SmimeError> = Vec::new();
                match cms_utils::verify_message_digest(&signer.digest_algorithm, signer.authenticated_attributes.as_ref(), content) {
                    Ok(_) => checks.message_digest_matches_content = true,
                    Err(e) => deferred_failures.push(e),
                }
                match cms_utils::verify_detached_signature(
                    pk,
                    &signer.digest_algorithm,
                    &signer.digest_encryption_algorithm,
                    signer.authenticated_attributes.as_ref().unwrap(),
                    signer.encrypted_digest,
                ) {
                    Ok(_) => checks.signature_matches_signed_data = true,
                    Err(e) => result.failures.push(e),
                }

                if checks.signature_matches_signed_data && checks.message_digest_matches_content {
                    return true;
                }

                // WildDuck workaround; TODO: remove when WildDuck is fixed
                let normalized = normalize_wildduck_content(content, inner_message);
                if cms_utils::verify_message_digest(&signer.digest_algorithm, signer.authenticated_attributes.as_ref(), &normalized).is_ok()
                {
                    checks.message_digest_matches_content = true;
                }
                if checks.message_digest_matches_content && checks.signature_matches_signed_data {
                    result.signed_content = Some(normalized);
                    result.failures.push(SmimeError::WildDuckWorkaround);
                    console_log!("Message digest matched with WildDuck workaround");
                    return true;
                }

                result.failures.extend(deferred_failures);
                false
            }
            SignedTarget::EContent(content) => {
                if has_signed_attrs {
                    match cms_utils::verify_message_digest(&signer.digest_algorithm, signer.authenticated_attributes.as_ref(), content) {
                        Ok(_) => checks.message_digest_matches_content = true,
                        Err(e) => result.failures.push(e),
                    }
                }
                match cms_utils::verify_econtent_signature(
                    pk,
                    &signer.digest_algorithm,
                    &signer.digest_encryption_algorithm,
                    signer.authenticated_attributes.as_ref(),
                    signer.encrypted_digest,
                    content,
                ) {
                    Ok(_) => checks.signature_matches_signed_data = true,
                    Err(e) => result.failures.push(e),
                }
                checks.signature_matches_signed_data && (!has_signed_attrs || checks.message_digest_matches_content)
            }
        }
    }
}

pub(crate) fn verify_signed_data(
    signed_data: &cryptography_x509::pkcs7::SignedData<'_>,
    target: SignedTarget<'_>,
    trust_stores: &[TrustStore],
    ca_file_pem: Option<&[u8]>,
    outer_from: Option<&mail_parser::Addr<'_>>,
    outer_date: Option<DateTime<Utc>>,
    result: &mut SmimeValidationResult,
) {
    let (certs, signers, ca_certs, inner_message) =
        match prepare_signed_data_verification(signed_data, target.content(), trust_stores, ca_file_pem, outer_from, outer_date, result) {
            Some(v) => v,
            None => return,
        };
    let builder = match build_policy_builder(&ca_certs) {
        Ok(b) => b,
        Err(e) => {
            result.failures.push(e);
            return;
        }
    };
    let verifier = match builder.build_email_verifier() {
        Ok(v) => v,
        Err(e) => {
            result.failures.push(SmimeError::BuildVerifier { err: e.to_string() });
            return;
        }
    };
    let inner_from_addr = inner_message.from().and_then(|address| address.first().cloned());
    let inner_date = inner_message.date().and_then(mail_parser_date_to_chrono);
    let trust_store_label = format!("{:?}", trust_stores);
    let mut sender_resolver = SenderResolver::default();

    for (idx, signer) in signers.iter().enumerate() {
        let (signing_time, signer_candidates) = match prepare_signer(signer, &certs, idx, result) {
            Some(v) => v,
            None => continue,
        };

        let has_signed_attrs = signer.authenticated_attributes.is_some();
        if let Some(err) = target.precheck_signer(has_signed_attrs) {
            result.failures.push(err);
            continue;
        }

        let mut signer_leaf = None;
        for signer_candidate in signer_candidates.iter() {
            let mut checks = SignatureChecks::default();
            let pk = match (KeyCryptoOps {}).public_key(signer_candidate) {
                Ok(pk) => pk,
                Err(e) => {
                    result.failures.push(SmimeError::ChainValidation {
                        fp: sha256_fingerprint_hex(signer_candidate).unwrap_or_else(|| "<encoding error>".to_string()),
                        idx,
                        err: e.to_string(),
                    });
                    continue;
                }
            };

            if target.verify_candidate(&pk, signer, has_signed_attrs, &inner_message, &mut checks, result) {
                signer_leaf = Some((*signer_candidate, checks));
                break;
            }
        }

        let (signer_leaf, mut checks) = match signer_leaf {
            None => continue,
            Some(t) => t,
        };

        if let Some(ct) = inner_message.content_type() {
            let (rfc9788, rfc9788_hp) = extract_rfc9788_info(ct);
            checks.rfc9788 = rfc9788;
            checks.rfc9788_hp = rfc9788_hp;
        }
        let mut entry = build_signer_entry(signer_leaf, signer, signing_time, checks, &trust_store_label, outer_date);
        let (chain, cert_trusted, chain_failures) = validate_chain(signer_leaf, &certs, &verifier, idx);
        entry.chain = chain;
        entry.validation_details.certificate_trusted_valid = cert_trusted;
        result.failures.extend(chain_failures);
        let crypto_valid = entry.validation_details.checks.signature_matches_signed_data
            && (entry.validation_details.checks.message_digest_matches_content || !has_signed_attrs);
        entry.signature_valid = crypto_valid && cert_trusted;
        resolve_sender(&mut entry, inner_from_addr.as_ref(), inner_date, outer_date, &mut sender_resolver, result);
        result.signers.push(entry);
    }
}

/// draft-ietf-lamps-cms-euf-cma-signeddata §5.1: detect eContent that is a
/// DER-encoded SignedAttributes (SET OF Attribute with contentType + messageDigest).
fn econtent_looks_like_signed_attrs(content: &[u8]) -> bool {
    use crate::cryptography_x509::csr::Attribute;
    let attrs: asn1::SetOf<'_, Attribute<'_>> = match asn1::parse_single(content) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut has_content_type = false;
    let mut has_message_digest = false;
    for attr in attrs {
        match attr.type_id {
            CONTENT_TYPE_OID => has_content_type = true,
            MESSAGE_DIGEST_OID => has_message_digest = true,
            _ => {}
        }
    }
    has_content_type && has_message_digest
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{SigningSystem, TrustStore, email_domain_to_a_label, verify_smime_from_eml_detailed};

    #[wasm_bindgen_test]
    fn wasm_email_domain_to_a_label() {
        assert_eq!(email_domain_to_a_label("alice@example.com"), "alice@example.com");
        assert_eq!(email_domain_to_a_label("user@δοκιμή.ελ"), "user@xn--jxalpdlp.xn--qxam");
    }

    #[wasm_bindgen_test]
    fn wasm_verify_unsigned_eml() {
        let eml = "From: test@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nBody\r\n".to_string();
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Builtin].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.signers.is_empty());
    }
}
