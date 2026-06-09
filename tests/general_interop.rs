use smime::errors::SmimeError;
use smime::{SigningSystem, TrustStore, verify_smime_from_eml_detailed};
use std::fs;

fn verify(file_path: &str) -> smime::SmimeValidationResult {
    let eml = fs::read_to_string(file_path).unwrap_or_else(|_| panic!("Failed to read {}", file_path));
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
    println!("Result for {}: {:#?}", file_path, result);
    result
}

/// An S/MIME message whose signature must not verify: no signer, no content,
/// no sender or date taken from the message.
fn assert_rejected(file_path: &str) {
    let result = verify(file_path);

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
    assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
    assert!(result.date.is_none());
}

fn assert_verified(
    file_path: &str,
    from_address: &str,
    from_comment: Option<&str>,
    signing_system: SigningSystem,
    date: &str,
    signing_time: &str,
) {
    let result = verify(file_path);

    assert_eq!(result.from_address.as_deref(), Some(from_address));
    assert_eq!(result.from_comment.as_deref(), from_comment);
    assert_eq!(result.signing_system, signing_system);
    assert!(result.failures.is_empty(), "Unexpected failures: {:?}", result.failures);
    assert!(!result.signers.is_empty() && result.signed_content.is_some());
    assert!(result.signers[0].signature_valid);
    assert_eq!(result.date.unwrap().to_rfc3339(), date);
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), signing_time);
}

#[test]
fn test_no_crypto_complex() {
    let result = verify("tests/general/no-crypto-complex.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_no_crypto() {
    let result = verify("tests/general/no-crypto.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_pkcs7_mime() {
    let result = verify("tests/general/pkcs7-mime.eml");

    assert_eq!(result.from_address, Some("aliceDss@examples.com".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
    assert!(!result.failures.is_empty() && result.signers.is_empty());
    assert!(!result.date.is_none());
}

#[test]
fn test_pkcs7_mime_missing_from() {
    let file_path = "tests/general/pkcs7-mime.eml";
    let eml = fs::read_to_string(file_path).expect("Failed to read file");
    let eml: String = eml.lines().filter(|line| !line.starts_with("From:")).map(|line| format!("{line}\r\n")).collect();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
    println!("Result for {}: {:#?}", file_path, result);

    assert_eq!(result.from_address, None);
    assert!(result.failures.contains(&SmimeError::MissingFrom));
}

#[test]
fn test_smime_enc_signed_complex_injected_minimal_legacy_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-minimal-legacy-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_minimal_legacy() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-minimal-legacy.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_minimal_lgc_rpl() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-minimal-lgc-rpl.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_minimal_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-minimal-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_minimal() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-minimal.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_strong_legacy_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-strong-legacy-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_strong_legacy() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-strong-legacy.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_strong_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-strong-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_injected_strong() {
    assert_rejected("tests/general/smime-enc-signed-complex-injected-strong.eml");
}

#[test]
fn test_smime_enc_signed_complex_wrapped_minimal_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-wrapped-minimal-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_wrapped_minimal() {
    assert_rejected("tests/general/smime-enc-signed-complex-wrapped-minimal.eml");
}

#[test]
fn test_smime_enc_signed_complex_wrapped_strong_reply() {
    assert_rejected("tests/general/smime-enc-signed-complex-wrapped-strong-reply.eml");
}

#[test]
fn test_smime_enc_signed_complex_wrapped_strong() {
    assert_rejected("tests/general/smime-enc-signed-complex-wrapped-strong.eml");
}

#[test]
fn test_smime_enc_signed_complex() {
    assert_rejected("tests/general/smime-enc-signed-complex.eml");
}

#[test]
fn test_smime_enc_signed_injected_minimal_legacy_reply() {
    assert_rejected("tests/general/smime-enc-signed-injected-minimal-legacy-reply.eml");
}

#[test]
fn test_smime_enc_signed_injected_minimal_legacy() {
    assert_rejected("tests/general/smime-enc-signed-injected-minimal-legacy.eml");
}

#[test]
fn test_smime_enc_signed_injected_minimal_reply() {
    assert_rejected("tests/general/smime-enc-signed-injected-minimal-reply.eml");
}

#[test]
fn test_smime_enc_signed_injected_minimal() {
    assert_rejected("tests/general/smime-enc-signed-injected-minimal.eml");
}

#[test]
fn test_smime_enc_signed_injected_strong_legacy_reply() {
    assert_rejected("tests/general/smime-enc-signed-injected-strong-legacy-reply.eml");
}

#[test]
fn test_smime_enc_signed_injected_strong_legacy() {
    assert_rejected("tests/general/smime-enc-signed-injected-strong-legacy.eml");
}

#[test]
fn test_smime_enc_signed_injected_strong_reply() {
    assert_rejected("tests/general/smime-enc-signed-injected-strong-reply.eml");
}

#[test]
fn test_smime_enc_signed_injected_strong() {
    assert_rejected("tests/general/smime-enc-signed-injected-strong.eml");
}

#[test]
fn test_smime_enc_signed_wrapped_minimal_reply() {
    assert_rejected("tests/general/smime-enc-signed-wrapped-minimal-reply.eml");
}

#[test]
fn test_smime_enc_signed_wrapped_minimal() {
    assert_rejected("tests/general/smime-enc-signed-wrapped-minimal.eml");
}

#[test]
fn test_smime_enc_signed_wrapped_strong_reply() {
    assert_rejected("tests/general/smime-enc-signed-wrapped-strong-reply.eml");
}

#[test]
fn test_smime_enc_signed_wrapped_strong() {
    assert_rejected("tests/general/smime-enc-signed-wrapped-strong.eml");
}

#[test]
fn test_smime_enc_signed() {
    assert_rejected("tests/general/smime-enc-signed.eml");
}

#[test]
fn test_smime_multipart_complex_injected() {
    assert_verified(
        "tests/general/smime-multipart-complex-injected.eml",
        "alice@smime.example",
        None,
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T17:07:02+00:00",
        "2021-02-20T17:07:02+00:00",
    );
}

#[test]
fn test_smime_multipart_complex_wrapped() {
    assert_verified(
        "tests/general/smime-multipart-complex-wrapped.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T17:05:02+00:00",
        "2021-02-20T17:05:02+00:00",
    );
}

#[test]
fn test_smime_multipart_complex() {
    assert_verified(
        "tests/general/smime-multipart-complex.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T17:02:02+00:00",
        "2021-02-20T17:02:02+00:00",
    );
}

#[test]
fn test_smime_multipart_injected() {
    assert_verified(
        "tests/general/smime-multipart-injected.eml",
        "alice@smime.example",
        None,
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T15:07:02+00:00",
        "2021-02-20T15:07:02+00:00",
    );
}

#[test]
fn test_smime_multipart_wrapped() {
    assert_verified(
        "tests/general/smime-multipart-wrapped.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T15:05:02+00:00",
        "2021-02-20T15:05:02+00:00",
    );
}

#[test]
fn test_smime_multipart() {
    assert_verified(
        "tests/general/smime-multipart.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MultipartSignedSMIME,
        "2021-02-20T15:02:02+00:00",
        "2021-02-20T15:02:02+00:00",
    );
}

#[test]
fn test_smime_one_part_complex_injected() {
    assert_verified(
        "tests/general/smime-one-part-complex-injected.eml",
        "alice@smime.example",
        None,
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T17:06:02+00:00",
        "2021-02-20T17:06:02+00:00",
    );
}

#[test]
fn test_smime_one_part_complex_wrapped() {
    assert_verified(
        "tests/general/smime-one-part-complex-wrapped.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T17:04:02+00:00",
        "2021-02-20T17:04:02+00:00",
    );
}

#[test]
fn test_smime_one_part_complex() {
    assert_verified(
        "tests/general/smime-one-part-complex.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T17:01:02+00:00",
        "2021-02-20T17:01:02+00:00",
    );
}

#[test]
fn test_smime_one_part_injected() {
    assert_verified(
        "tests/general/smime-one-part-injected.eml",
        "alice@smime.example",
        None,
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T15:06:02+00:00",
        "2021-02-20T15:06:02+00:00",
    );
}

#[test]
fn test_smime_one_part_wrapped() {
    assert_verified(
        "tests/general/smime-one-part-wrapped.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T15:04:02+00:00",
        "2021-02-20T15:04:02+00:00",
    );
}

#[test]
fn test_smime_one_part() {
    assert_verified(
        "tests/general/smime-one-part.eml",
        "alice@smime.example",
        Some("Alice"),
        SigningSystem::MIMEPartSMIME,
        "2021-02-20T15:01:02+00:00",
        "2021-02-20T15:01:02+00:00",
    );
}

#[test]
fn test_general_test_0() {
    let result = verify("tests/general/test_0.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_0_signed() {
    assert_verified(
        "tests/general/test_0_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T16:18:00+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_1() {
    let result = verify("tests/general/test_1.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_1_signed() {
    assert_verified(
        "tests/general/test_1_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T13:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_1_utf8_signed() {
    assert_verified(
        "tests/general/test_1_utf8_signed.eml",
        "lõks@naide.ee",
        None,
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T13:28:16+00:00",
        "2026-01-19T17:05:18+00:00",
    );
}

#[test]
fn test_general_test_1_utf8_idn_signed() {
    assert_verified(
        "tests/general/test_1_utf8_idn_signed.eml",
        "lõks@näide.ee",
        None,
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T13:28:16+00:00",
        "2026-01-19T16:07:45+00:00",
    );
}

#[test]
fn test_general_test_2() {
    let result = verify("tests/general/test_2.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_2_signed() {
    assert_verified(
        "tests/general/test_2_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T13:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_3() {
    let result = verify("tests/general/test_3.eml");

    assert_eq!(result.from_address, None);
    assert_eq!(result.from_comment, None);
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.signers.is_empty() && result.signed_content.is_none());
    assert!(matches!(result.failures[..], [SmimeError::NoSmimeSig]));
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_3_signed() {
    assert_verified(
        "tests/general/test_3_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T13:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_attachment_0() {
    let result = verify("tests/general/test_multipart_attachment_0.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_attachment_0_signed() {
    assert_verified(
        "tests/general/test_multipart_attachment_0_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-07T16:26:00+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_attachment_1() {
    let result = verify("tests/general/test_multipart_attachment_1.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_attachment_1_signed() {
    assert_verified(
        "tests/general/test_multipart_attachment_1_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:11:40+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_attachment_2() {
    let result = verify("tests/general/test_multipart_attachment_2.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_attachment_2_signed() {
    assert_verified(
        "tests/general/test_multipart_attachment_2_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:11:40+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_attachment_3() {
    let result = verify("tests/general/test_multipart_attachment_3.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_attachment_3_signed() {
    assert_verified(
        "tests/general/test_multipart_attachment_3_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:11:40+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_text_0() {
    let result = verify("tests/general/test_multipart_text_0.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_text_0_signed() {
    assert_verified(
        "tests/general/test_multipart_text_0_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T16:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_text_1() {
    let result = verify("tests/general/test_multipart_text_1.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_text_1_signed() {
    assert_verified(
        "tests/general/test_multipart_text_1_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T16:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_text_2() {
    let result = verify("tests/general/test_multipart_text_2.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_text_2_signed() {
    assert_verified(
        "tests/general/test_multipart_text_2_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T16:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_multipart_text_3() {
    let result = verify("tests/general/test_multipart_text_3.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_multipart_text_3_signed() {
    assert_verified(
        "tests/general/test_multipart_text_3_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T16:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_0() {
    let result = verify("tests/general/test_rfc822_0.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_0_signed() {
    assert_verified(
        "tests/general/test_rfc822_0_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T15:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_1() {
    let result = verify("tests/general/test_rfc822_1.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_1_signed() {
    assert_verified(
        "tests/general/test_rfc822_1_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T15:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_2() {
    let result = verify("tests/general/test_rfc822_2.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_2_signed() {
    assert_verified(
        "tests/general/test_rfc822_2_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T15:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_3() {
    let result = verify("tests/general/test_rfc822_3.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_3_signed() {
    assert_verified(
        "tests/general/test_rfc822_3_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T15:28:16+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_multipart_attachment_0() {
    let result = verify("tests/general/test_rfc822_multipart_attachment_0.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_multipart_attachment_0_signed() {
    assert_verified(
        "tests/general/test_rfc822_multipart_attachment_0_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:24:05+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_multipart_attachment_1() {
    let result = verify("tests/general/test_rfc822_multipart_attachment_1.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_multipart_attachment_1_signed() {
    assert_verified(
        "tests/general/test_rfc822_multipart_attachment_1_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:24:05+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_multipart_attachment_2() {
    let result = verify("tests/general/test_rfc822_multipart_attachment_2.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_multipart_attachment_2_signed() {
    assert_verified(
        "tests/general/test_rfc822_multipart_attachment_2_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:24:05+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_general_test_rfc822_multipart_attachment_3() {
    let result = verify("tests/general/test_rfc822_multipart_attachment_3.eml");
    assert_eq!(result.signing_system, SigningSystem::Other);
    assert!(result.date.is_none());
}

#[test]
fn test_general_test_rfc822_multipart_attachment_3_signed() {
    assert_verified(
        "tests/general/test_rfc822_multipart_attachment_3_signed.eml",
        "loks@naide.ee",
        Some("Lõks"),
        SigningSystem::MultipartSignedSMIME,
        "2026-01-06T14:24:05+00:00",
        "2026-01-19T15:36:47+00:00",
    );
}

#[test]
fn test_rfc9788_multipart_complex_hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-multipart-complex-hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:07:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert!(result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, Some("clear".to_string()));
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:07:02+00:00");
}

#[test]
fn test_rfc9788_multipart_complex_rfc8551hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-multipart-complex-rfc8551hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, Some("Alice".to_string()));
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:27:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, None);
    assert!(!result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:27:02+00:00");
}

#[test]
fn test_rfc9788_multipart_hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-multipart-hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert!(result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, Some("clear".to_string()));
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
}

#[test]
fn test_rfc9788_multipart_hp_wd() {
    let eml = fs::read_to_string("tests/header-protection/smime-multipart-hp-invalid.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert_eq!(result.failures.iter().filter(|f| matches!(f, SmimeError::WildDuckWorkaround)).count(), 1);
    assert!(result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, Some("clear".to_string()));
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
}

#[test]
fn test_rfc9788_one_part_complex_hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-one-part-complex-hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:06:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert!(result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, Some("clear".to_string()));
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:06:02+00:00");
}

#[test]
fn test_rfc9788_one_part_complex_rfc8551hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-one-part-complex-rfc8551hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, Some("Alice".to_string()));
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, None);
    assert!(!result.signers[0].validation_details.checks.rfc9788);
}

#[test]
fn test_rfc9788_one_part_hp() {
    let eml = fs::read_to_string("tests/header-protection/smime-one-part-hp.eml").unwrap();
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

    assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
    assert_eq!(result.from_comment, None);
    assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:06:02+00:00");
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].signature_valid);
    assert!(result.signers[0].validation_details.checks.rfc9788);
    assert_eq!(result.signers[0].validation_details.checks.rfc9788_hp, Some("clear".to_string()));
    assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:06:02+00:00");
}
