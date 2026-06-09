use crate::cryptography_x509::pkcs7::{Content, ContentInfo};
use crate::cryptography_x509_verification::policy;
use crate::errors::SmimeError;
use crate::types;
use crate::types::{SignerValidation, SigningSystem, SmimeValidationResult, TrustConfig, TrustStore};
use crate::{
    SignedTarget, SmimeContentKind, decrypt, extract_smime_opaque_p7m_der, smime_content_kind, verify_signed_data,
    verify_smime_from_eml_detailed,
};
use chrono::{TimeZone, Utc};
use mail_parser::{MessageParser, MimeHeaders};

const MAX_DECRYPT_DEPTH: usize = 4;

/// Decrypt and/or verify an S/MIME message.
pub fn decrypt_and_verify_smime_from_eml_detailed(
    eml_text: String,
    trust: TrustConfig,
    keys: &decrypt::DecryptionKeys,
) -> SmimeValidationResult {
    let trust_stores = trust.stores;
    let ca_file_pem = trust.ca_file_pem.as_deref();
    let mut current_eml = eml_text;
    let mut accumulated_signers: Vec<SignerValidation> = Vec::new();
    let mut outer_encryption_info: Option<types::EncryptionInfo> = None;
    let mut outer_from_address: Option<String> = None;
    let mut outer_from_comment: Option<String> = None;
    let mut outer_date: Option<chrono::DateTime<Utc>> = None;

    for depth in 0..MAX_DECRYPT_DEPTH {
        let mut result = decrypt_and_verify_one_layer(current_eml, trust_stores.clone(), keys, ca_file_pem);

        // TODO: properly record each encryption layer's info instead of just the first
        if outer_encryption_info.is_none() {
            outer_encryption_info = result.encryption_info.take();
        }
        if depth == 0 {
            outer_from_address = result.from_address.clone();
            outer_from_comment = result.from_comment.clone();
            outer_date = result.date;
        }
        accumulated_signers.extend(std::mem::take(&mut result.signers));

        // If signed_content is S/MIME, continue processing the next layer
        if let Some(ref content) = result.signed_content
            && let Ok(inner_eml) = std::str::from_utf8(content)
            && let Some(inner_msg) = MessageParser::default().parse(inner_eml.as_bytes())
            && is_smime_mime(&inner_msg)
        {
            current_eml = inner_eml.to_string();
            continue;
        }

        // No more S/MIME layers to process - finalize
        result.signers = accumulated_signers;
        if result.encryption_info.is_none() {
            result.encryption_info = outer_encryption_info;
        }
        if result.from_address.is_none() {
            result.from_address = outer_from_address;
        }
        if result.from_comment.is_none() {
            result.from_comment = outer_from_comment;
        }
        if result.date.is_none() {
            result.date = outer_date;
        }
        return result;
    }

    SmimeValidationResult {
        signing_system: SigningSystem::Other,
        signers: accumulated_signers,
        failures: vec![SmimeError::DecryptionFailed { err: format!("nesting depth exceeds maximum of {}", MAX_DECRYPT_DEPTH) }],
        signed_content: None,
        from_address: outer_from_address,
        from_comment: outer_from_comment,
        date: outer_date,
        encryption_info: outer_encryption_info,
    }
}

/// Process one layer of decrypted and signed data
fn decrypt_and_verify_one_layer(
    eml_text: String,
    trust_stores: Vec<TrustStore>,
    keys: &decrypt::DecryptionKeys,
    ca_file_pem: Option<&[u8]>,
) -> SmimeValidationResult {
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
            result.failures.push(SmimeError::ParseEml);
            return result;
        }
    };

    let content_type = match message.content_type() {
        Some(ct) => ct,
        None => {
            result.failures.push(SmimeError::MissingContentType);
            return result;
        }
    };

    let is_pkcs7_mime = smime_content_kind(content_type) == SmimeContentKind::Pkcs7Mime;

    if !is_pkcs7_mime {
        let trust = TrustConfig { stores: trust_stores, ca_file_pem: ca_file_pem.map(<[u8]>::to_vec) };
        return verify_smime_from_eml_detailed(eml_text, trust);
    }

    let p7_der = match extract_smime_opaque_p7m_der(&message) {
        Ok(der) => der,
        Err(e) => {
            result.failures.push(e);
            return result;
        }
    };

    let content_info = match asn1::parse_single::<ContentInfo>(&p7_der) {
        Ok(ci) => ci,
        Err(e) => {
            result.failures.push(SmimeError::ParsePkcs7Msg { err: e.to_string() });
            return result;
        }
    };

    let outer_from = message.from().and_then(|f| f.first());
    result.from_address = outer_from.and_then(|a| a.address().map(|s| s.to_string()));
    result.from_comment = outer_from.and_then(|a| a.name.as_ref().map(|n| n.to_string()));
    result.date = message.date().and_then(|d| Utc.timestamp_opt(d.to_timestamp(), 0).single());

    match content_info.content {
        Content::EnvelopedData(ed) => {
            decrypt_enveloped_data_layer(&ed.into_inner(), keys, &mut result);
        }
        Content::AuthEnvelopedData(aed) => {
            decrypt_auth_enveloped_data_layer(&aed.into_inner(), keys, &mut result);
        }
        Content::SignedData(sd) => {
            let sd_inner = *sd.into_inner();

            result.signing_system = SigningSystem::MIMEPartSMIME;
            let from_addr = result.from_address.clone();
            let from_comment = result.from_comment.clone();
            let date = result.date;
            let outer_from_addr = from_addr.as_deref().map(|addr| mail_parser::Addr::new(from_comment.as_deref(), addr));
            match SignedTarget::econtent(&sd_inner) {
                Ok(target) => {
                    verify_signed_data(&sd_inner, target, &trust_stores, ca_file_pem, outer_from_addr.as_ref(), date, &mut result)
                }
                Err(e) => result.failures.push(e),
            }
        }
        _ => {
            result.failures.push(SmimeError::NoPkcs7Content);
        }
    }

    result
}

fn is_smime_mime(msg: &mail_parser::Message<'_>) -> bool {
    msg.content_type().is_some_and(|ct| matches!(smime_content_kind(ct), SmimeContentKind::Pkcs7Mime | SmimeContentKind::SignedMultipart))
}

fn summarize_recipient_infos<'a>(
    recipient_infos: &crate::cryptography_x509::common::Asn1ReadableOrWritable<
        asn1::SetOf<'a, crate::cryptography_x509::pkcs7::RecipientInfo<'a>>,
        asn1::SetOfWriter<'a, crate::cryptography_x509::pkcs7::RecipientInfo<'a>>,
    >,
) -> Vec<types::RecipientInfoSummary> {
    use crate::cryptography_x509::common::AlgorithmParameters as AP;
    use crate::cryptography_x509::pkcs7::{KeyAgreeRecipientIdentifier, RecipientIdentifier, RecipientInfo};

    recipient_infos
        .unwrap_read()
        .clone()
        .flat_map(|ri| match ri {
            RecipientInfo::KeyTransRecipientInfo(ktri) => {
                let key_enc = match &ktri.key_encryption_algorithm.params {
                    AP::RSA(_) => "RSAES-PKCS#1-v1.5".into(),
                    AP::RsaesOaep(_) => "RSAES-OAEP".into(),
                    AP::Other(oid, _) => format!("Unknown ({})", oid),
                    _ => "Unknown".into(),
                };
                let (issuer, serial_number) = match &ktri.rid {
                    RecipientIdentifier::IssuerAndSerialNumber(ias) => {
                        (policy::extension::dn_to_string(ias.issuer.unwrap_read()), hex::encode(ias.serial_number.as_bytes()))
                    }
                    RecipientIdentifier::SubjectKeyIdentifier(ski) => ("SubjectKeyIdentifier".into(), hex::encode(ski)),
                };
                vec![types::RecipientInfoSummary { issuer, serial_number, key_encryption_algorithm: key_enc }]
            }
            RecipientInfo::KeyAgreeRecipientInfo(kari) => {
                let key_enc: String = decrypt::ecdh_algorithm_name(kari.key_encryption_algorithm.oid());
                kari.recipient_encrypted_keys
                    .unwrap_read()
                    .clone()
                    .map(|rek| {
                        let (issuer, serial_number) = match &rek.rid {
                            KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias) => {
                                (policy::extension::dn_to_string(ias.issuer.unwrap_read()), hex::encode(ias.serial_number.as_bytes()))
                            }
                            KeyAgreeRecipientIdentifier::RKeyId(rkid) => {
                                ("RecipientKeyIdentifier".into(), hex::encode(rkid.subject_key_identifier))
                            }
                        };
                        types::RecipientInfoSummary { issuer, serial_number, key_encryption_algorithm: key_enc.clone() }
                    })
                    .collect()
            }
            _ => vec![],
        })
        .collect()
}

/// Decrypt an AuthEnvelopedData (RFC 5083), populate EncryptionInfo, and
/// set signed_content to the decrypted plaintext for further processing.
fn decrypt_auth_enveloped_data_layer(
    auth_enveloped: &crate::cryptography_x509::pkcs7::AuthEnvelopedData<'_>,
    keys: &decrypt::DecryptionKeys,
    result: &mut SmimeValidationResult,
) {
    use crate::cryptography_x509::common::AlgorithmParameters as AP;

    // RFC 5083 §2.1: version MUST be 0
    if auth_enveloped.version != 0 {
        result.failures.push(SmimeError::CmsVersionMismatch {
            structure: "AuthEnvelopedData".into(),
            expected: 0,
            actual: auth_enveloped.version,
            idx: None,
        });
    }

    let cea = &auth_enveloped.auth_encrypted_content_info.content_encryption_algorithm.params;
    let (cipher, key_size) = match cea {
        AP::Aes128Gcm(_) => ("AES-GCM", "128-bit"),
        AP::Aes192Gcm(_) => ("AES-GCM", "192-bit"),
        AP::Aes256Gcm(_) => ("AES-GCM", "256-bit"),
        AP::Aes128Ccm(_) => ("AES-CCM", "128-bit"),
        AP::Aes192Ccm(_) => ("AES-CCM", "192-bit"),
        AP::Aes256Ccm(_) => ("AES-CCM", "256-bit"),
        _ => ("Unknown", "unknown"),
    };

    let recipients = summarize_recipient_infos(&auth_enveloped.recipient_infos);
    result.encryption_info = Some(types::EncryptionInfo { cipher: cipher.into(), key_size: key_size.into(), recipients });

    let plaintext = match decrypt::decrypt_auth_enveloped_data(auth_enveloped, keys) {
        Ok((Some(pt), warnings)) => {
            result.failures.extend(warnings);
            pt
        }
        Ok((None, _)) => return,
        Err(e) => {
            result.failures.push(e);
            return;
        }
    };

    result.signed_content = Some(plaintext);
}

/// Decrypt an EnvelopedData, populate EncryptionInfo, and set signed_content
/// to the decrypted plaintext for further processing.
/// This works on EnvelopedData and thus cannot claim anything about the authenticity of the encrypted data.
fn decrypt_enveloped_data_layer(
    enveloped_data: &crate::cryptography_x509::pkcs7::EnvelopedData<'_>,
    keys: &decrypt::DecryptionKeys,
    result: &mut SmimeValidationResult,
) {
    use crate::cryptography_x509::common::AlgorithmParameters as AP;
    use crate::cryptography_x509::pkcs7::RecipientInfo;

    // RFC 5652 §6.1: validate EnvelopedData version
    {
        use crate::cryptography_x509::pkcs7::{CertificateChoices, RevocationInfoChoice};

        let has_originator_info = enveloped_data.originator_info.is_some();
        let has_unprotected_attrs = enveloped_data.unprotected_attrs.is_some();
        let has_other_cert_in_oi = enveloped_data.originator_info.as_ref().is_some_and(|oi| {
            oi.certs.as_ref().is_some_and(|cs| cs.unwrap_read().clone().any(|c| matches!(c, CertificateChoices::OtherCertificate(_))))
        });
        let has_other_crl_in_oi = enveloped_data.originator_info.as_ref().is_some_and(|oi| {
            oi.crls.as_ref().is_some_and(|crls| crls.unwrap_read().clone().any(|c| matches!(c, RevocationInfoChoice::Other(_))))
        });
        let has_v2_attr_cert_in_oi = enveloped_data.originator_info.as_ref().is_some_and(|oi| {
            oi.certs.as_ref().is_some_and(|cs| cs.unwrap_read().clone().any(|c| matches!(c, CertificateChoices::V2AttrCert(_))))
        });
        let has_pwri_or_ori = enveloped_data
            .recipient_infos
            .unwrap_read()
            .clone()
            .any(|ri| matches!(ri, RecipientInfo::PasswordRecipientInfo(_) | RecipientInfo::OtherRecipientInfo(_)));
        let all_ri_v0 = enveloped_data.recipient_infos.unwrap_read().clone().all(|ri| match ri {
            RecipientInfo::KeyTransRecipientInfo(ktri) => ktri.version == 0,
            _ => false,
        });
        let expected_version: u8 = if has_other_cert_in_oi || has_other_crl_in_oi {
            4
        } else if has_v2_attr_cert_in_oi || has_pwri_or_ori {
            3
        } else if !has_originator_info && !has_unprotected_attrs && all_ri_v0 {
            0
        } else {
            2
        };
        if enveloped_data.version != expected_version {
            result.failures.push(SmimeError::CmsVersionMismatch {
                structure: "EnvelopedData".into(),
                expected: expected_version,
                actual: enveloped_data.version,
                idx: None,
            });
        }
    }

    // Build encryption info from the envelope
    let cea = &enveloped_data.encrypted_content_info.content_encryption_algorithm.params;
    let (cipher, key_size) = match cea {
        AP::Aes128Cbc(_) => ("AES-CBC", "128-bit"),
        AP::Aes192Cbc(_) => ("AES-CBC", "192-bit"),
        AP::Aes256Cbc(_) => ("AES-CBC", "256-bit"),
        AP::DesEde3Cbc(_) => ("3DES-CBC", "168-bit"),
        AP::Rc2Cbc(_) => ("RC2-CBC", "unknown"),
        _ => ("Unknown", "unknown"),
    };
    let recipients = summarize_recipient_infos(&enveloped_data.recipient_infos);
    result.encryption_info = Some(types::EncryptionInfo { cipher: cipher.into(), key_size: key_size.into(), recipients });

    // Decrypt
    let plaintext = match decrypt::decrypt_enveloped_data(enveloped_data, keys) {
        Ok((Some(pt), warnings)) => {
            result.failures.extend(warnings);
            pt
        }
        Ok((None, _)) => return,
        Err(e) => {
            result.failures.push(e);
            return;
        }
    };

    result.signed_content = Some(plaintext);
}
