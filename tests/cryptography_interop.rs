#[cfg(test)]
mod tests {
    use smime::errors::SmimeError;
    use smime::{SigningSystem, TrustStore, verify_smime_from_eml_detailed};
    use std::fs;

    #[test]
    fn test_rsa_pss_wd() {
        let file_path = "tests/general/signed-rsa-pss-wildduck.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(!result.signers.is_empty(), "No signers parsed from RSA-PSS signed message");
        assert_eq!(result.signers.len(), 1);
        assert!(
            result.signers[0].validation_details.checks.signature_matches_signed_data,
            "RSA-PSS signature should verify over SignedAttributes"
        );
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.from_address, Some("taavi@zone.ee".to_string()));
        assert_eq!(result.from_comment, Some("Taavi Eomäe".to_string()));
        assert_eq!(result.date.unwrap().to_rfc3339(), "2026-02-06T15:07:00+00:00".to_string());
        assert_eq!(result.failures.iter().filter(|f| matches!(f, SmimeError::WildDuckWorkaround)).count(), 1);
    }

    #[test]
    fn test_signed_rsa_pss() {
        let file_path = "tests/general/signed-rsa-pss.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);

        assert_eq!(result.signing_system, SigningSystem::MultipartSignedSMIME);
        assert!(!result.signers.is_empty(), "No signers parsed from RSA-PSS signed message");
        assert!(
            result.signers[0].validation_details.checks.signature_matches_signed_data,
            "RSA-PSS signature should verify over SignedAttributes"
        );
    }

    #[test]
    fn test_256() {
        let eml = fs::read_to_string("tests/general/test_256_utf8_signed.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].signature_valid);
    }

    #[test]
    fn test_384() {
        let eml = fs::read_to_string("tests/general/test_384_utf8_signed.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].signature_valid);
    }

    #[test]
    fn test_512() {
        let eml = fs::read_to_string("tests/general/test_512_utf8_signed.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].signature_valid);
    }

    #[test]
    fn test_unsupported_digest_alg() {
        let eml = fs::read_to_string("tests/general/unsupported-digest-alg.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);

        assert!(
            result.failures.iter().any(|f| matches!(f, SmimeError::UnsupportedDigestAlg { .. })),
            "expected UnsupportedDigestAlg, got: {:?}",
            result.failures
        );
    }

    #[test]
    fn test_sha1() {
        let file_path = "tests/general/sha1.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        println!("Result for {}: {:#?}", file_path, result);

        let all_invalid = result.signers.iter().all(|s| !s.signature_valid);
        assert!(all_invalid || result.signers.is_empty());
        assert!(result.failures.iter().any(|f| matches!(
            f,
            SmimeError::UnsupportedDigestAlg { .. } | SmimeError::UnsupportedSignatureAlg { .. } | SmimeError::DisallowedDigestAlg { .. }
        )));
    }

    #[test]
    fn test_ml_dsa_44() {
        let eml = fs::read_to_string("tests/pq/ml-dsa-44.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"ML-DSA-44 signed-data example with signed attributes".as_slice()));
    }

    #[test]
    fn test_ml_dsa_65() {
        let eml = fs::read_to_string("tests/pq/ml-dsa-65.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"ML-DSA-65 signed-data example with signed attributes".as_slice()));
    }

    #[test]
    fn test_ml_dsa_87() {
        let eml = fs::read_to_string("tests/pq/ml-dsa-87.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"ML-DSA-87 signed-data example with signed attributes".as_slice()));
    }

    #[test]
    fn test_ed448() {
        // Ed448 fixture is OpenSSL-generated. Our verification doesn't support Ed448 yet,
        // so we just confirm the message is recognized as signed and produces a SigVerify error.
        let eml = fs::read_to_string("tests/general/test_sig_ed448.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert!(result.failures.iter().any(|f| matches!(f, SmimeError::SigVerify { .. })));
    }

    #[test]
    fn test_ed25519() {
        let eml = fs::read_to_string("tests/general/ed25519.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"Hello from Ed25519!".as_slice()));
    }

    #[test]
    fn test_rsa_sha256() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_sha256.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_sha384() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_sha384.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_sha512() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_sha512.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_pss_sha384() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_pss_sha384.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_pss_sha512() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_pss_sha512.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_digest_sha3_256() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_digest_sha3_256.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_digest_sha3_384() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_digest_sha3_384.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1, "failures: {:?}", result.failures);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_rsa_digest_sha3_512() {
        let eml = fs::read_to_string("tests/general/test_sig_rsa_digest_sha3_512.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nRSA signature test")));
    }

    #[test]
    fn test_ml_dsa_44_shake128() {
        let eml = fs::read_to_string("tests/pq/ml-dsa-44-shake128.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"Hello from ML-DSA-44-SHAKE128!".as_slice()));
    }

    #[test]
    fn test_ml_dsa_44_shake() {
        let eml = fs::read_to_string("tests/pq/ml-dsa-44-shake.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.signed_content.as_deref(), Some(b"Hello from ML-DSA-44-SHAKE!".as_slice()));
    }

    #[test]
    fn test_no_message_digest_attr() {
        let eml = fs::read_to_string("tests/general/no-message-digest-attr.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, SmimeError::DigestVerify { err } if err.contains("message-digest attribute missing"))),
            "expected missing message-digest error, got: {:?}",
            result.failures
        );
    }

    #[test]
    fn test_no_auth_attrs() {
        let eml = fs::read_to_string("tests/general/no-auth-attrs.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        // RFC 5652 §5.4: when signedAttrs is absent, signature covers eContent directly
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(!result.signers[0].validation_details.checks.message_digest_matches_content);
        assert!(
            result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nNo authenticated attributes"))
        );
    }

    #[test]
    fn test_rfc4134_4_2_signed_rsa_no_attrs() {
        let eml = fs::read_to_string("tests/rfc4134/4.2-signed-rsa-no-attrs.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        // SHA-1 is disallowed, so signature verification fails
        assert!(
            result.failures.iter().any(|f| matches!(f, SmimeError::UnsupportedDigestAlg { .. } | SmimeError::DisallowedDigestAlg { .. }))
        );
        assert_eq!(result.signed_content.as_deref(), Some(b"This is some sample content.".as_slice()));
    }

    #[test]
    fn test_rfc4134_4_5_signed_rsa_all() {
        let eml = fs::read_to_string("tests/rfc4134/4.5-signed-rsa-all.eml").expect("read");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        // BER indefinite-length + constructed OCTET STRING; SHA-1 is disallowed
        assert!(
            result.failures.iter().any(|f| matches!(f, SmimeError::UnsupportedDigestAlg { .. } | SmimeError::DisallowedDigestAlg { .. }))
        );
        assert_eq!(result.signed_content.as_deref(), Some(b"This is some sample content.".as_slice()));
    }
}
