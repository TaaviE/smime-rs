use crate::cryptography_x509::certificate::Certificate;
use crate::cryptography_x509::common::AlgorithmParameters;
use crate::cryptography_x509_verification::ops::CryptoOps;
use crate::cryptography_x509_verification::policy::Policy;
use crate::cryptography_x509_verify::error::CryptographyError;
use crate::errors::SmimeError;
use crate::utils::truncate_middle;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

/// Which signing system was used to sign the message
#[wasm_bindgen]
#[derive(Clone, Serialize, Debug, PartialEq)]
pub enum SigningSystem {
    /// Signature is multipart/signed and S/MIME
    MultipartSignedSMIME,
    /// Signature is application/pkcs7-mime (CMS, S/MIME)
    MIMEPartSMIME,
    /// Signature is multipart/signed and PGP
    MultipartSignedPGP,
    /// Signature is application/pgp (PGP)
    MIMEPartPGP,
    /// Unknown or missing
    Other,
}

/// Checks related to the cryptographic signature and its representation
#[derive(Serialize, Clone, Default, Tsify)]
pub struct SignatureChecks {
    /// Signature is valid over signed data (message digest)
    pub signature_matches_signed_data: bool,
    /// Message digest matches content
    pub message_digest_matches_content: bool,
    /// Other non-critical notes or warnings
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub other_notes: Vec<SmimeError>,
    /// Which type of RFC 9788 Header Protection is used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfc9788_hp: Option<String>,
    /// If the signature uses RFC 9788
    pub rfc9788: bool,
    /// Email addresses in signer certificate
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub certificate_emails: Vec<String>,
    /// Names in signer certificate
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub certificate_names: Vec<String>,
}

impl fmt::Debug for SignatureChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("SignatureChecks");
        ds.field("signature_valid", &self.signature_matches_signed_data)
            .field("message_digest_valid", &self.message_digest_matches_content)
            .field("other_notes", &self.other_notes);

        match &self.rfc9788_hp {
            Some(v) => ds.field("rfc9788_hp", v),
            None => ds.field("rfc9788_hp", &None::<String>),
        };

        ds.field("rfc9788", &self.rfc9788)
            .field("certificate_san_emails", &self.certificate_emails)
            .field("certificate_san_names", &self.certificate_names);

        ds.finish()
    }
}

/// Debug information about the validation process
#[derive(Clone, Serialize, Tsify)]
pub struct ValidationDetails {
    /// Which trust store was used to validate the certificate.
    pub trust_store_used: String,
    /// If the certificate itself is valid
    pub certificate_trusted_valid: bool,
    /// Certificate of this signer
    pub certificate: String,
    /// Status asserted by a verified stapled OCSP response (see [`crate::ocsp`]),
    /// pinned to the trust-anchored issuer;
    /// A verified `revoked` staple clears `certificate_trusted_valid`.
    /// `None` when there is no staple for the signer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<crate::ocsp::StapledStatus>,
    /// If all the SCTs are valid (trust unknown)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scts_valid: Option<bool>,
    /// Other non-critical notes or warnings
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub other_notes: Vec<SmimeError>,
    /// Checks done with the signature itself
    pub checks: SignatureChecks,
}

impl fmt::Debug for ValidationDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ValidationDebug");
        ds.field("trust_store_used", &self.trust_store_used)
            .field("certificate_valid", &self.certificate_trusted_valid)
            .field("certificate", &truncate_middle(&self.certificate, 64));
        //.field("certificate", &self.certificate);

        ds.field("revocation_status", &self.revocation_status);

        match &self.scts_valid {
            Some(v) => ds.field("sct_valid", v),
            None => ds.field("sct_valid", &None::<bool>),
        };

        ds.field("other_notes", &self.other_notes).field("checks", &self.checks).finish()
    }
}

/// Result of one specific signer/signature
/// There may be more than one signature
#[derive(Clone, Serialize, Tsify)]
pub struct SignerValidation {
    /// Final result of the validation
    /// Composite of certificate trust, checks done on the certificate and signature
    pub signature_valid: bool,
    /// The chain of certificates to a trusted root, as fingerprints
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub chain: Vec<String>,
    /// Detailed information about the validation process
    pub validation_details: ValidationDetails,
    /// Signing time from the PKCS#7 structure
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(type = "string")]
    pub signing_time: Option<DateTime<Utc>>,
}

impl fmt::Debug for SignerValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerValidation")
            .field("valid", &self.signature_valid)
            .field("chain", &self.chain)
            .field("details", &self.validation_details)
            .field("signing_time", &self.signing_time)
            .finish()
    }
}

/// Information about a single CMS RecipientInfo
#[derive(Clone, Debug, Serialize, Tsify)]
pub struct RecipientInfoSummary {
    /// Issuer distinguished name
    pub issuer: String,
    /// Serial number (hex)
    pub serial_number: String,
    /// Key encryption algorithm, RFC name (e.g. `RSAES-PKCS1-v1_5`, `RSAES-OAEP`)
    pub key_encryption_algorithm: String,
}

/// Information about the encryption layer of the message
#[derive(Clone, Debug, Serialize, Tsify)]
pub struct EncryptionInfo {
    /// Content encryption cipher without key size (e.g. `AES-CBC`, `3DES-CBC`, `RC2-CBC`)
    pub cipher: String,
    /// Key size (e.g. `128-bit`, `192-bit`, `256-bit`)
    pub key_size: String,
    /// All recipients listed in the EnvelopedData
    pub recipients: Vec<RecipientInfoSummary>,
}

/// The complete signature result
#[derive(Clone, Serialize, Tsify)]
pub struct SmimeValidationResult {
    /// Which signing system was used to sign the message
    pub signing_system: SigningSystem,
    /// Who were the signers and if their signatures were valid
    pub signers: Vec<SignerValidation>,
    /// Errors that occurred during validation
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[tsify(optional)]
    pub failures: Vec<SmimeError>,
    /// Content that was actually signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_content: Option<Vec<u8>>,
    /// Sender address that can be displayed to the user
    pub from_address: Option<String>,
    /// Sender comment/name that can be displayed to the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_comment: Option<String>,
    /// Date of the message
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(type = "string")]
    pub date: Option<DateTime<Utc>>,
    /// Encryption layer information (populated when EnvelopedData is encountered)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub encryption_info: Option<EncryptionInfo>,
}

impl fmt::Debug for SmimeValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("SmimeValidationResult");
        ds.field("signing_system", &self.signing_system).field("signers", &self.signers).field("failures", &self.failures);

        match &self.signed_content {
            Some(v) => ds.field("signed_content", &truncate_middle(&String::from_utf8_lossy(v), 64)),
            None => ds.field("signed_content", &None::<String>),
        };

        match &self.from_address {
            Some(v) => ds.field("from_address", v),
            None => ds.field("from_address", &None::<String>),
        };

        match &self.from_comment {
            Some(v) => ds.field("from_comment", v),
            None => ds.field("from_comment", &None::<String>),
        };

        match &self.date {
            Some(v) => ds.field("date", &v.to_rfc3339()),
            None => ds.field("date", &None::<String>),
        };

        match &self.encryption_info {
            Some(v) => ds.field("encryption_info", v),
            None => ds.field("encryption_info", &None::<EncryptionInfo>),
        };

        ds.finish()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStore {
    /// Builtin trust store (Mozilla S/MIME trust store)
    Builtin,
    /// Debug certificates
    Debug,
}

/// Trust anchors for verification: zero or more embedded [`TrustStore`]s plus an
/// optional custom CA bundle (PEM). A plain `Vec<TrustStore>` converts into this
/// via `From`, so existing callers need no changes.
#[derive(Debug, Clone, Default)]
pub struct TrustConfig {
    pub stores: Vec<TrustStore>,
    pub ca_file_pem: Option<Vec<u8>>,
}

impl From<Vec<TrustStore>> for TrustConfig {
    fn from(stores: Vec<TrustStore>) -> Self {
        TrustConfig { stores, ca_file_pem: None }
    }
}

pub type CryptographyResult<T> = Result<T, CryptographyError>;

#[derive(Clone)]
pub struct KeyCryptoOps {}
impl CryptoOps for KeyCryptoOps {
    // An enum that can represent the common public key families we accept.
    // We purposefully keep payloads simple (OID and raw subjectPublicKey bytes)
    // because verification is handled elsewhere.
    type Key = AnyPublicKey;
    type Err = CryptographyError;
    type CertificateExtra<'a> = Certificate<'a>;
    type PolicyExtra<'a> = Policy<'a, Self>;

    fn public_key(&self, cert: &Certificate<'_>) -> CryptographyResult<Self::Key> {
        let spki = &cert.tbs_cert.spki;
        let alg = &spki.algorithm;
        let spki_der = asn1::write_single(spki)?;

        let key = match alg.params.clone() {
            AlgorithmParameters::RSA(_) | AlgorithmParameters::RsaPss(_) => AnyPublicKey::RSA { algorithm: alg.oid().clone(), spki_der },
            AlgorithmParameters::Ed25519 => AnyPublicKey::Ed25519 { algorithm: alg.oid().clone(), spki_der },
            AlgorithmParameters::Ed448 => AnyPublicKey::Ed448 { algorithm: alg.oid().clone(), spki_der },
            AlgorithmParameters::ECDSA(Some(crate::cryptography_x509::common::EcParameters::NamedCurve(curve))) => match curve {
                crate::cryptography_x509::oid::EC_SECP384R1 => AnyPublicKey::P384 { algorithm: alg.oid().clone(), spki_der },
                crate::cryptography_x509::oid::EC_SECP256R1 => AnyPublicKey::P256 { algorithm: alg.oid().clone(), spki_der },
                crate::cryptography_x509::oid::EC_SECP521R1 => AnyPublicKey::P521 { algorithm: alg.oid().clone(), spki_der },
                _ => {
                    return Err(CryptographyError::from(
                        SmimeError::UnsupportedPublicKey { detail: "unknown named curve".into() }.localize("en-UK"),
                    ));
                }
            },
            AlgorithmParameters::ECDSA(_) => {
                return Err(CryptographyError::from(
                    SmimeError::UnsupportedPublicKey { detail: "unknown public key algorithm".into() }.localize("en-UK"),
                ));
            }
            AlgorithmParameters::MlDsa44 => AnyPublicKey::MLDSA44 { algorithm: alg.oid().clone(), spki_der },
            AlgorithmParameters::MlDsa65 => AnyPublicKey::MLDSA65 { algorithm: alg.oid().clone(), spki_der },
            AlgorithmParameters::MlDsa87 => AnyPublicKey::MLDSA87 { algorithm: alg.oid().clone(), spki_der },
            _ => {
                return Err(CryptographyError::from(
                    SmimeError::UnsupportedPublicKey { detail: "unknown public key algorithm".into() }.localize("en-UK"),
                ));
            }
        };

        Ok(key)
    }

    fn verify_signed_by<'a>(&self, cert: &Certificate<'a>, issuer_public_key: &Self::Key) -> CryptographyResult<()> {
        crate::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm(
            issuer_public_key,
            &cert.signature_alg,
            cert.signature.as_bytes(),
            &asn1::write_single(&cert.tbs_cert)?,
        )
    }

    fn clone_public_key(key: &Self::Key) -> Self::Key {
        key.clone()
    }

    fn clone_extra<'a>(extra: &Self::CertificateExtra<'a>) -> Self::CertificateExtra<'a> {
        extra.clone()
    }
}

#[derive(Clone, Debug)]
pub enum AnyPublicKey {
    RSA { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    P256 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    P384 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    P521 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    Ed25519 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    Ed448 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    MLDSA44 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    MLDSA65 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
    MLDSA87 { algorithm: asn1::ObjectIdentifier, spki_der: Vec<u8> },
}
