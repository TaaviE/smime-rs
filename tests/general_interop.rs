#[cfg(test)]
mod tests {
    use smime::errors::SmimeError;
    use smime::{SigningSystem, TrustStore, verify_smime_from_eml_detailed};
    use std::fs;

    #[test]
    fn test_no_crypto_complex() {
        let file_path = "tests/general/no-crypto-complex.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_no_crypto() {
        let file_path = "tests/general/no-crypto.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }
    #[test]
    fn test_pkcs7_mime() {
        let file_path = "tests/general/pkcs7-mime.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

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
        let file_path = "tests/general/smime-enc-signed-complex-injected-minimal-legacy-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_minimal_legacy() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-minimal-legacy.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_minimal_lgc_rpl() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-minimal-lgc-rpl.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_minimal_reply() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-minimal-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_minimal() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-minimal.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_strong_legacy_reply() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-strong-legacy-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_strong_legacy() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-strong-legacy.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_strong_reply() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-strong-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_injected_strong() {
        let file_path = "tests/general/smime-enc-signed-complex-injected-strong.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_wrapped_minimal_reply() {
        let file_path = "tests/general/smime-enc-signed-complex-wrapped-minimal-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_wrapped_minimal() {
        let file_path = "tests/general/smime-enc-signed-complex-wrapped-minimal.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_wrapped_strong_reply() {
        let file_path = "tests/general/smime-enc-signed-complex-wrapped-strong-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex_wrapped_strong() {
        let file_path = "tests/general/smime-enc-signed-complex-wrapped-strong.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_complex() {
        let file_path = "tests/general/smime-enc-signed-complex.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }
    #[test]
    fn test_smime_enc_signed_injected_minimal_legacy_reply() {
        let file_path = "tests/general/smime-enc-signed-injected-minimal-legacy-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_minimal_legacy() {
        let file_path = "tests/general/smime-enc-signed-injected-minimal-legacy.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_minimal_reply() {
        let file_path = "tests/general/smime-enc-signed-injected-minimal-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_minimal() {
        let file_path = "tests/general/smime-enc-signed-injected-minimal.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_strong_legacy_reply() {
        let file_path = "tests/general/smime-enc-signed-injected-strong-legacy-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_strong_legacy() {
        let file_path = "tests/general/smime-enc-signed-injected-strong-legacy.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_strong_reply() {
        let file_path = "tests/general/smime-enc-signed-injected-strong-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_injected_strong() {
        let file_path = "tests/general/smime-enc-signed-injected-strong.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_wrapped_minimal_reply() {
        let file_path = "tests/general/smime-enc-signed-wrapped-minimal-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_wrapped_minimal() {
        let file_path = "tests/general/smime-enc-signed-wrapped-minimal.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_wrapped_strong_reply() {
        let file_path = "tests/general/smime-enc-signed-wrapped-strong-reply.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed_wrapped_strong() {
        let file_path = "tests/general/smime-enc-signed-wrapped-strong.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_enc_signed() {
        let file_path = "tests/general/smime-enc-signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(!result.failures.is_empty() && result.signers.is_empty() && result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_smime_multipart_complex_injected() {
        let file_path = "tests/general/smime-multipart-complex-injected.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:07:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:07:02+00:00");
    }

    #[test]
    fn test_smime_multipart_complex_wrapped() {
        let file_path = "tests/general/smime-multipart-complex-wrapped.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:05:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:05:02+00:00");
    }

    #[test]
    fn test_smime_multipart_complex() {
        let file_path = "tests/general/smime-multipart-complex.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:02:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:02:02+00:00");
    }

    #[test]
    fn test_smime_multipart_injected() {
        let file_path = "tests/general/smime-multipart-injected.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:07:02+00:00");
    }

    #[test]
    fn test_smime_multipart_wrapped() {
        let file_path = "tests/general/smime-multipart-wrapped.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:05:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:05:02+00:00");
    }

    #[test]
    fn test_smime_multipart() {
        let file_path = "tests/general/smime-multipart.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:02:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:02:02+00:00");
    }

    #[test]
    fn test_smime_one_part_complex_injected() {
        let file_path = "tests/general/smime-one-part-complex-injected.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:06:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:06:02+00:00");
    }

    #[test]
    fn test_smime_one_part_complex_wrapped() {
        let file_path = "tests/general/smime-one-part-complex-wrapped.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:04:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:04:02+00:00");
    }

    #[test]
    fn test_smime_one_part_complex() {
        let file_path = "tests/general/smime-one-part-complex.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T17:01:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T17:01:02+00:00");
    }

    #[test]
    fn test_smime_one_part_injected() {
        let file_path = "tests/general/smime-one-part-injected.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:06:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:06:02+00:00");
    }

    #[test]
    fn test_smime_one_part_wrapped() {
        let file_path = "tests/general/smime-one-part-wrapped.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:04:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:04:02+00:00");
    }

    #[test]
    fn test_smime_one_part() {
        let file_path = "tests/general/smime-one-part.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("alice@smime.example".to_string()));
        assert_eq!(result.from_comment, Some("Alice".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2021-02-20T15:01:02+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2021-02-20T15:01:02+00:00");
    }

    #[test]
    fn test_general_test_0() {
        let file_path = "tests/general/test_0.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_0_signed() {
        let file_path = "tests/general/test_0_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.from_comment, Some("Lõks".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T16:18:00+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T15:36:47+00:00");
    }

    #[test]
    fn test_general_test_1() {
        let file_path = "tests/general/test_1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_1_signed() {
        let file_path = "tests/general/test_1_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.from_comment, Some("Lõks".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T13:28:16+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T15:36:47+00:00");
    }

    #[test]
    fn test_general_test_1_utf8_signed() {
        let file_path = "tests/general/test_1_utf8_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("lõks@naide.ee".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T13:28:16+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T17:05:18+00:00");
    }

    #[test]
    fn test_general_test_1_utf8_idn_signed() {
        let file_path = "tests/general/test_1_utf8_idn_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("lõks@näide.ee".to_string()));
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T13:28:16+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T16:07:45+00:00");
    }

    #[test]
    fn test_general_test_2() {
        let file_path = "tests/general/test_2.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_2_signed() {
        let file_path = "tests/general/test_2_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.from_comment, Some("Lõks".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T13:28:16+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T15:36:47+00:00");
    }

    #[test]
    fn test_general_test_3() {
        let file_path = "tests/general/test_3.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, None);
        assert_eq!(result.from_comment, None);
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(!result.failures.is_empty() || result.signers.is_empty() || result.signed_content.is_none());
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_3_signed() {
        let file_path = "tests/general/test_3_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.from_comment, Some("Lõks".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert!(result.failures.is_empty() && !result.signers.is_empty() && result.signed_content.is_some());
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T13:28:16+00:00");
        assert_eq!(result.signers[0].signing_time.unwrap().to_rfc3339(), "2026-01-19T15:36:47+00:00");
    }

    #[test]
    fn test_general_test_multipart_attachment_0() {
        let file_path = "tests/general/test_multipart_attachment_0.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_attachment_0_signed() {
        let file_path = "tests/general/test_multipart_attachment_0_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-07T16:26:00+00:00");
    }

    #[test]
    fn test_general_test_multipart_attachment_1() {
        let file_path = "tests/general/test_multipart_attachment_1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_attachment_1_signed() {
        let file_path = "tests/general/test_multipart_attachment_1_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:11:40+00:00");
    }

    #[test]
    fn test_general_test_multipart_attachment_2() {
        let file_path = "tests/general/test_multipart_attachment_2.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_attachment_2_signed() {
        let file_path = "tests/general/test_multipart_attachment_2_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:11:40+00:00");
    }

    #[test]
    fn test_general_test_multipart_attachment_3() {
        let file_path = "tests/general/test_multipart_attachment_3.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_attachment_3_signed() {
        let file_path = "tests/general/test_multipart_attachment_3_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:11:40+00:00");
    }

    #[test]
    fn test_general_test_multipart_text_0() {
        let file_path = "tests/general/test_multipart_text_0.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_text_0_signed() {
        let file_path = "tests/general/test_multipart_text_0_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T16:28:16+00:00");
    }

    #[test]
    fn test_general_test_multipart_text_1() {
        let file_path = "tests/general/test_multipart_text_1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_text_1_signed() {
        let file_path = "tests/general/test_multipart_text_1_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T16:28:16+00:00");
    }

    #[test]
    fn test_general_test_multipart_text_2() {
        let file_path = "tests/general/test_multipart_text_2.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_text_2_signed() {
        let file_path = "tests/general/test_multipart_text_2_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T16:28:16+00:00");
    }

    #[test]
    fn test_general_test_multipart_text_3() {
        let file_path = "tests/general/test_multipart_text_3.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_multipart_text_3_signed() {
        let file_path = "tests/general/test_multipart_text_3_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T16:28:16+00:00");
    }

    #[test]
    fn test_general_test_rfc822_0() {
        let file_path = "tests/general/test_rfc822_0.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_0_signed() {
        let file_path = "tests/general/test_rfc822_0_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T15:28:16+00:00");
    }

    #[test]
    fn test_general_test_rfc822_1() {
        let file_path = "tests/general/test_rfc822_1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_1_signed() {
        let file_path = "tests/general/test_rfc822_1_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T15:28:16+00:00");
    }

    #[test]
    fn test_general_test_rfc822_2() {
        let file_path = "tests/general/test_rfc822_2.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_2_signed() {
        let file_path = "tests/general/test_rfc822_2_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T15:28:16+00:00");
    }

    #[test]
    fn test_general_test_rfc822_3() {
        let file_path = "tests/general/test_rfc822_3.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_3_signed() {
        let file_path = "tests/general/test_rfc822_3_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T15:28:16+00:00");
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_0() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_0.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_0_signed() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_0_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:24:05+00:00");
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_1() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_1_signed() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_1_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:24:05+00:00");
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_2() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_2.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_2_signed() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_2_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:24:05+00:00");
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_3() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_3.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::Other);
        assert!(result.date.is_none());
    }

    #[test]
    fn test_general_test_rfc822_multipart_attachment_3_signed() {
        let file_path = "tests/general/test_rfc822_multipart_attachment_3_signed.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.from_address, Some("loks@naide.ee".to_string()));
        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-01-06T14:24:05+00:00");
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
}
