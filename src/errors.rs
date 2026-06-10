use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::collections::HashMap;
use unic_langid::LanguageIdentifier;

/// Various errors that might be encountered during signature processing
#[derive(Clone, Debug, PartialEq)]
pub enum SmimeError {
    // Errors
    ReadEml {
        path: String,
        err: String,
    },
    ParseEml,
    MissingContentType,
    MissingBoundary,
    MissingFrom,
    NoSmimeSig,
    BuildVerifier {
        err: String,
    },
    ParseInner,
    MsgNotEnoughParts,
    NoSigSubpart,
    ParsePkcs7Sig {
        err: String,
    },
    ExtractMultipart {
        err: String,
    },
    NoPkcs7Mime,
    ParsePkcs7Msg {
        err: String,
    },
    NoPkcs7Content,
    LoadCaBundle {
        store: String,
        err: String,
    },
    PolicySetup {
        step: String,
        err: String,
    },
    ChainValidation {
        fp: String,
        idx: usize,
        err: String,
    },
    UnsupportedPublicKey {
        detail: String,
    },
    DigestVerify {
        err: String,
    },
    UnsupportedDigestAlg {
        alg: String,
        idx: usize,
    },
    DisallowedDigestAlg {
        alg: String,
        idx: usize,
    },
    UnsupportedSignatureAlg {
        alg: String,
        idx: usize,
    },
    DisallowedSignatureAlg {
        alg: String,
        idx: usize,
    },
    SigVerify {
        err: String,
    },
    SignerCertNotFound {
        id: String,
    },
    OtherNameParseError {
        err: String,
        hex_data: String,
    },
    MissingContentTypeAttr {
        idx: usize,
    },
    ContentTypeMismatch {
        idx: usize,
    },
    MalformedContentTypeAttr {
        idx: usize,
    },
    UnexpectedEContentType,
    DecryptionFailed {
        err: String,
    },
    UnsupportedKeyEncryptionAlg {
        alg: String,
    },
    UnsupportedContentEncryptionAlg {
        alg: String,
    },
    NoMatchingRecipient,
    PrivateKeyParseFailed {
        err: String,
    },
    /// A stapled OCSP response revokes a certificate in the verified chain (the
    /// leaf or an intermediate CA), which invalidates the certificate.
    StapledOcspRevoked {
        subject: String,
    },
    Pkcs12PasswordRequired,
    Pkcs12WrongPassword,
    Pkcs12NoCertificate,
    Pkcs12NoPrivateKey,
    Pkcs12Parse {
        err: String,
    },
    Raw(String),
    // Warnings
    CmsVersionMismatch {
        structure: String,
        expected: u8,
        actual: u8,
        idx: Option<usize>,
    },
    AttributeCardinality {
        attr: String,
        idx: usize,
    },
    DateMismatch {
        msg: String,
        date_a: String,
        date_b: String,
    },
    WildDuckWorkaround,
    CertPolicyWarning {
        detail: String,
    },
    DigestAlgorithmWarning {
        detail: String,
        idx: usize,
    },
    AlgorithmProtectionMismatch {
        field: String,
        idx: usize,
    },
    LocalPartCaseMismatch {
        from: String,
        cert: String,
    },
    RsaPssParameterWarning {
        detail: String,
        idx: usize,
    },
    Pbkdf2LowIterationCount {
        iterations: u64,
    },
    WeakContentEncryptionAlg {
        alg: String,
    },
    WeakKeyEncryptionAlg {
        alg: String,
    },
}

impl SmimeError {
    pub fn identifier(&self) -> &'static str {
        match self {
            // Errors
            SmimeError::ReadEml { .. } => "err-read-eml",
            SmimeError::ParseEml => "err-parse-eml",
            SmimeError::MissingContentType => "err-missing-content-type",
            SmimeError::MissingBoundary => "err-missing-boundary",
            SmimeError::MissingFrom => "err-missing-from",
            SmimeError::NoSmimeSig => "err-no-smime-sig",
            SmimeError::BuildVerifier { .. } => "err-build-verifier",
            SmimeError::ParseInner => "err-parse-inner",
            SmimeError::MsgNotEnoughParts => "err-msg-not-enough-parts",
            SmimeError::NoSigSubpart => "err-no-sig-subpart",
            SmimeError::ParsePkcs7Sig { .. } => "err-parse-pkcs7-sig",
            SmimeError::ExtractMultipart { .. } => "err-extract-multipart",
            SmimeError::NoPkcs7Mime => "err-no-pkcs7-mime",
            SmimeError::ParsePkcs7Msg { .. } => "err-parse-pkcs7-msg",
            SmimeError::NoPkcs7Content => "err-no-pkcs7-content",
            SmimeError::LoadCaBundle { .. } => "err-load-ca-bundle",
            SmimeError::PolicySetup { .. } => "err-policy-setup",
            SmimeError::ChainValidation { .. } => "err-chain-validation",
            SmimeError::UnsupportedPublicKey { .. } => "err-unsupported-public-key",
            SmimeError::DigestVerify { .. } => "err-digest-verify",
            SmimeError::UnsupportedDigestAlg { .. } => "err-unsupported-digest-alg",
            SmimeError::DisallowedDigestAlg { .. } => "err-disallowed-digest-alg",
            SmimeError::UnsupportedSignatureAlg { .. } => "err-unsupported-signature-alg",
            SmimeError::DisallowedSignatureAlg { .. } => "err-disallowed-signature-alg",
            SmimeError::SigVerify { .. } => "err-sig-verify",
            SmimeError::SignerCertNotFound { .. } => "err-signer-cert-not-found",
            SmimeError::OtherNameParseError { .. } => "err-other-name-parse",
            SmimeError::MissingContentTypeAttr { .. } => "err-missing-content-type-attr",
            SmimeError::ContentTypeMismatch { .. } => "err-content-type-mismatch",
            SmimeError::MalformedContentTypeAttr { .. } => "err-malformed-content-type-attr",
            SmimeError::UnexpectedEContentType => "err-unexpected-econtent-type",
            SmimeError::DecryptionFailed { .. } => "err-decryption-failed",
            SmimeError::UnsupportedKeyEncryptionAlg { .. } => "err-unsupported-key-encryption-alg",
            SmimeError::UnsupportedContentEncryptionAlg { .. } => "err-unsupported-content-encryption-alg",
            SmimeError::NoMatchingRecipient => "err-no-matching-recipient",
            SmimeError::PrivateKeyParseFailed { .. } => "err-private-key-parse-failed",
            SmimeError::StapledOcspRevoked { .. } => "err-stapled-ocsp-revoked",
            SmimeError::Pkcs12PasswordRequired => "err-pkcs12-password-required",
            SmimeError::Pkcs12WrongPassword => "err-pkcs12-wrong-password",
            SmimeError::Pkcs12NoCertificate => "err-pkcs12-no-certificate",
            SmimeError::Pkcs12NoPrivateKey => "err-pkcs12-no-private-key",
            SmimeError::Pkcs12Parse { .. } => "err-pkcs12-parse",
            SmimeError::Raw(_) => "raw",
            // Warnings
            SmimeError::CmsVersionMismatch { .. } => "warn-cms-version-mismatch",
            SmimeError::AttributeCardinality { .. } => "warn-attribute-cardinality",
            SmimeError::DateMismatch { .. } => "warn-date-mismatch",
            SmimeError::WildDuckWorkaround => "warn-wildduck",
            SmimeError::CertPolicyWarning { .. } => "warn-cert-policy",
            SmimeError::DigestAlgorithmWarning { .. } => "warn-digest-algorithm",
            SmimeError::AlgorithmProtectionMismatch { .. } => "warn-algorithm-protection-mismatch",
            SmimeError::LocalPartCaseMismatch { .. } => "warn-local-part-case-mismatch",
            SmimeError::RsaPssParameterWarning { .. } => "warn-rsa-pss-parameter",
            SmimeError::Pbkdf2LowIterationCount { .. } => "warn-pbkdf2-low-iteration-count",
            SmimeError::WeakContentEncryptionAlg { .. } => "warn-weak-content-encryption-alg",
            SmimeError::WeakKeyEncryptionAlg { .. } => "warn-weak-key-encryption-alg",
        }
    }

    pub fn args(&self) -> HashMap<String, FluentValue<'_>> {
        let mut args = HashMap::new();
        match self {
            // Errors
            SmimeError::ReadEml { path, err } => {
                args.insert("path".to_string(), FluentValue::from(path.clone()));
                args.insert("err".to_string(), FluentValue::from(err.clone()));
            }
            SmimeError::BuildVerifier { err }
            | SmimeError::ParsePkcs7Sig { err }
            | SmimeError::ExtractMultipart { err }
            | SmimeError::ParsePkcs7Msg { err }
            | SmimeError::DigestVerify { err }
            | SmimeError::SigVerify { err }
            | SmimeError::DecryptionFailed { err }
            | SmimeError::PrivateKeyParseFailed { err }
            | SmimeError::Pkcs12Parse { err } => {
                args.insert("err".to_string(), FluentValue::from(err.clone()));
            }
            SmimeError::LoadCaBundle { store, err } => {
                args.insert("store".to_string(), FluentValue::from(store.clone()));
                args.insert("err".to_string(), FluentValue::from(err.clone()));
            }
            SmimeError::PolicySetup { step, err } => {
                args.insert("step".to_string(), FluentValue::from(step.clone()));
                args.insert("err".to_string(), FluentValue::from(err.clone()));
            }
            SmimeError::ChainValidation { fp, idx, err } => {
                args.insert("fp".to_string(), FluentValue::from(fp.clone()));
                args.insert("idx".to_string(), FluentValue::from(*idx));
                args.insert("err".to_string(), FluentValue::from(err.clone()));
            }
            SmimeError::UnsupportedPublicKey { detail } => {
                args.insert("detail".to_string(), FluentValue::from(detail.clone()));
            }
            SmimeError::UnsupportedDigestAlg { alg, idx }
            | SmimeError::DisallowedDigestAlg { alg, idx }
            | SmimeError::UnsupportedSignatureAlg { alg, idx }
            | SmimeError::DisallowedSignatureAlg { alg, idx } => {
                args.insert("alg".to_string(), FluentValue::from(alg.clone()));
                args.insert("idx".to_string(), FluentValue::from(*idx));
            }
            SmimeError::SignerCertNotFound { id } => {
                args.insert("id".to_string(), FluentValue::from(id.clone()));
            }
            SmimeError::OtherNameParseError { err, hex_data } => {
                args.insert("err".to_string(), FluentValue::from(err.clone()));
                args.insert("hex_data".to_string(), FluentValue::from(hex_data.clone()));
            }
            SmimeError::MissingContentTypeAttr { idx }
            | SmimeError::ContentTypeMismatch { idx }
            | SmimeError::MalformedContentTypeAttr { idx } => {
                args.insert("idx".to_string(), FluentValue::from(*idx));
            }
            SmimeError::UnsupportedKeyEncryptionAlg { alg } | SmimeError::UnsupportedContentEncryptionAlg { alg } => {
                args.insert("alg".to_string(), FluentValue::from(alg.clone()));
            }
            SmimeError::ParseEml
            | SmimeError::MissingContentType
            | SmimeError::MissingBoundary
            | SmimeError::MissingFrom
            | SmimeError::NoSmimeSig
            | SmimeError::ParseInner
            | SmimeError::MsgNotEnoughParts
            | SmimeError::NoSigSubpart
            | SmimeError::NoPkcs7Mime
            | SmimeError::NoPkcs7Content
            | SmimeError::UnexpectedEContentType
            | SmimeError::NoMatchingRecipient
            | SmimeError::Pkcs12PasswordRequired
            | SmimeError::Pkcs12WrongPassword
            | SmimeError::Pkcs12NoCertificate
            | SmimeError::Pkcs12NoPrivateKey
            | SmimeError::Raw(_) => {}
            // Warnings
            SmimeError::CmsVersionMismatch { structure, expected, actual, .. } => {
                args.insert("structure".to_string(), FluentValue::from(structure.clone()));
                args.insert("expected".to_string(), FluentValue::from(*expected));
                args.insert("actual".to_string(), FluentValue::from(*actual));
            }
            SmimeError::AttributeCardinality { attr, idx } => {
                args.insert("attr".to_string(), FluentValue::from(attr.clone()));
                args.insert("idx".to_string(), FluentValue::from(*idx));
            }
            SmimeError::DateMismatch { msg, date_a, date_b } => {
                args.insert("msg".to_string(), FluentValue::from(msg.clone()));
                args.insert("date_a".to_string(), FluentValue::from(date_a.clone()));
                args.insert("date_b".to_string(), FluentValue::from(date_b.clone()));
            }
            SmimeError::WildDuckWorkaround => {}
            SmimeError::CertPolicyWarning { detail } => {
                args.insert("detail".to_string(), FluentValue::from(detail.clone()));
            }
            SmimeError::DigestAlgorithmWarning { detail, idx } | SmimeError::RsaPssParameterWarning { detail, idx } => {
                args.insert("detail".to_string(), FluentValue::from(detail.clone()));
                args.insert("idx".to_string(), FluentValue::from(*idx));
            }
            SmimeError::AlgorithmProtectionMismatch { field, idx } => {
                args.insert("field".to_string(), FluentValue::from(field.clone()));
                args.insert("idx".to_string(), FluentValue::from(*idx));
            }
            SmimeError::LocalPartCaseMismatch { from, cert } => {
                args.insert("from".to_string(), FluentValue::from(from.clone()));
                args.insert("cert".to_string(), FluentValue::from(cert.clone()));
            }
            SmimeError::Pbkdf2LowIterationCount { iterations } => {
                args.insert("iterations".to_string(), FluentValue::from(*iterations));
            }
            SmimeError::WeakContentEncryptionAlg { alg } => {
                args.insert("alg".to_string(), FluentValue::from(alg.clone()));
            }
            SmimeError::WeakKeyEncryptionAlg { alg } => {
                args.insert("alg".to_string(), FluentValue::from(alg.clone()));
            }
            SmimeError::StapledOcspRevoked { subject } => {
                args.insert("subject".to_string(), FluentValue::from(subject.clone()));
            }
        }
        args
    }

    pub fn localize_en_uk(&self) -> String {
        self.localize("en-UK")
    }

    pub fn localize(&self, lang: &str) -> String {
        if let SmimeError::Raw(s) = self {
            return s.clone();
        }

        let ftl_string = include_str!("locales/en-UK/errors.ftl");
        let res = FluentResource::try_new(ftl_string.to_owned()).expect("Failed to parse an FTL resource.");

        let lang_id: LanguageIdentifier = lang.parse().unwrap_or_else(|_| "en-UK".parse().unwrap());
        let mut bundle = FluentBundle::new(vec![lang_id]);
        // Deliberate: interpolated values (subject names, addresses) can contain RTL
        // text, and terminal output needs FSI/PDI bidi isolation just like a GUI.
        bundle.set_use_isolating(true);
        bundle.add_resource(res).expect("Failed to add FTL resources to the bundle.");

        let msg = match bundle.get_message(self.identifier()) {
            Some(msg) => msg,
            None => return format!("Missing localization for {}", self.identifier()),
        };

        let pattern = match msg.value() {
            Some(pattern) => pattern,
            None => return format!("Message {} has no value", self.identifier()),
        };

        let mut args = FluentArgs::new();
        for (k, v) in self.args() {
            match v {
                FluentValue::String(s) => args.set(k, s),
                FluentValue::Number(n) => args.set(k, n),
                _ => {}
            }
        }

        let mut errors = vec![];
        bundle.format_pattern(pattern, Some(&args), &mut errors).to_string()
    }
}

impl Serialize for SmimeError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SmimeError", 2)?;
        match self {
            SmimeError::Raw(s) => {
                state.serialize_field("id", "raw")?;
                let mut args = HashMap::new();
                args.insert("err", s);
                state.serialize_field("args", &args)?;
            }
            _ => {
                state.serialize_field("id", self.identifier())?;

                let args = self.args();
                let mut serializable_args = HashMap::new();
                for (k, v) in args {
                    match v {
                        FluentValue::String(s) => {
                            serializable_args.insert(k, s.into_owned());
                        }
                        FluentValue::Number(n) => {
                            serializable_args.insert(k, n.as_string().to_string());
                        }
                        _ => {}
                    }
                }
                state.serialize_field("args", &serializable_args)?;
            }
        }
        state.end()
    }
}
