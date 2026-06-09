#![cfg(feature = "decrypt")]

#[cfg(test)]
mod tests {
    use smime::errors::SmimeError;
    use smime::{SigningSystem, TrustStore, verify_smime_from_eml_detailed};
    use std::fs;

    fn load_cert_der(key_path: &str) -> Vec<u8> {
        let cert_path = key_path.replace(".key", ".pem");
        pem::parse(fs::read(&cert_path).unwrap_or_else(|_| panic!("Failed to read {}", cert_path)))
            .expect("Failed to parse cert PEM")
            .into_contents()
    }

    /// Trust anchor for the nested fixtures, written by `create-cms nested`.
    fn nested_trust() -> smime::TrustConfig {
        smime::TrustConfig { stores: vec![], ca_file_pem: Some(include_bytes!("general/nested_root_ca.pem").to_vec()) }
    }

    fn assert_decrypted_ok(result: &smime::SmimeValidationResult, expected_content: &str) {
        assert!(result.encryption_info.is_some(), "No encryption_info; failures: {:?}", result.failures);
        let has_decrypt_err = result.failures.iter().any(|f| {
            matches!(f, SmimeError::DecryptionFailed { .. } | SmimeError::NoMatchingRecipient | SmimeError::PrivateKeyParseFailed { .. })
        });
        assert!(!has_decrypt_err, "Decryption failed: {:?}", result.failures);
        let content = result.signed_content.as_ref().expect("No signed_content after decryption");
        let content_str = std::str::from_utf8(content).expect("signed_content is not valid UTF-8");
        assert!(content_str.contains(expected_content), "Decrypted content doesn't contain {:?}, got: {:?}", expected_content, content_str);
    }

    #[test]
    fn pkcs12_extracted_key_decrypts() {
        let p12 = std::fs::read("tests/keys/test_rsa_sha1_aes128.p12").expect("Failed to read p12");
        let key_der = smime::pkcs12_utils::extract_private_key_from_p12(&p12, "zone.eu").expect("Failed to extract key");
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = std::fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("Failed to read eml");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![smime::TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
    }

    #[test]
    fn test_decrypted_content_matches_plaintext() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
    }

    #[test]
    fn test_decrypt_and_verify_aes256() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "256-bit");
        assert_eq!(enc.recipients.len(), 1);
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-PKCS#1-v1.5");
        assert!(!enc.recipients[0].serial_number.is_empty());
        assert!(enc.recipients[0].issuer.contains("Kalle"));
    }

    #[test]
    fn test_decrypt_and_verify_aes128() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes128.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "128-bit");
        assert_eq!(enc.recipients[0].serial_number, "33b8f8faeca461445cb7a59e88693a75ff7ad68d");
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("Failed to read file");
        // Use signing key (wrong key) for decryption - should fail
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa_sign.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa_sign.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        assert!(!result.failures.is_empty());
        assert!(result.encryption_info.is_some(), "encryption_info should still be populated");
        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "256-bit");
    }

    #[test]
    fn test_decrypt_aes192() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes192.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "192-bit");
    }

    #[test]
    fn test_decrypt_oaep_sha256() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "256-bit");
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    #[test]
    #[cfg(not(feature = "decrypt-3des"))]
    fn test_decrypt_unsupported_3des() {
        let eml = fs::read_to_string("tests/general/test_encrypted_3des.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        assert!(!result.failures.is_empty());
        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "3DES-CBC");
        assert_eq!(enc.key_size, "168-bit");
    }

    #[test]
    #[cfg(feature = "decrypt-3des")]
    fn test_decrypt_3des() {
        let eml = fs::read_to_string("tests/general/test_encrypted_3des.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        assert_decrypted_ok(&result, "3DES-CBC encrypted test message");
        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.cipher, "3DES-CBC");
        assert_eq!(enc.key_size, "168-bit");
    }

    #[test]
    fn test_decrypt_passthrough_signed_only() {
        let eml = fs::read_to_string("tests/general/pkcs7-mime.eml").expect("Failed to read file");
        let random_key = (0..32u8).map(|i| i.wrapping_mul(0x6D).wrapping_add(0xAB)).collect::<Vec<_>>();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml.clone(),
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &random_key, recipient_cert_der: &cert_der, ..Default::default() },
        );
        let reference = smime::verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());

        assert_eq!(result.signing_system, reference.signing_system);
        assert_eq!(result.from_address, reference.from_address);
        assert_eq!(result.failures.len(), reference.failures.len());
        assert!(result.encryption_info.is_none());
    }

    // OAEP with SHA-384 and SHA-512
    #[test]
    fn test_decrypt_oaep_sha384() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep384.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    #[test]
    fn test_decrypt_oaep_sha512() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep512.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    #[test]
    fn test_decrypt_invalid_key() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("Failed to read file");
        let garbage_key = (0..64u8).map(|i| i.wrapping_mul(0x6D).wrapping_add(0xDE)).collect::<Vec<_>>();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &garbage_key, recipient_cert_der: &cert_der, ..Default::default() },
        );

        let has_key_error = result.failures.iter().any(|f| matches!(f, SmimeError::PrivateKeyParseFailed { .. }));
        assert!(has_key_error, "Expected PrivateKeyParseFailed, got: {:?}", result.failures);
        assert!(result.encryption_info.is_some());
    }

    #[test]
    fn test_decrypt_oaep_sha1() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep_sha1.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "256-bit");
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    #[test]
    fn test_decrypt_oaep_aes128() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep_aes128.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "128-bit");
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    #[test]
    fn test_decrypt_aes192_oaep() {
        let eml = fs::read_to_string("tests/general/test_encrypted_oaep_aes192.eml").expect("Failed to read file");
        let key_der =
            pem::parse(fs::read("tests/keys/test_rsa.key").expect("Failed to read key")).expect("Failed to parse PEM").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().unwrap();
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "192-bit");
        assert_eq!(enc.recipients[0].key_encryption_algorithm, "RSAES-OAEP");
    }

    fn ec_decrypt_test(eml_path: &str, key_path: &str) {
        let eml = fs::read_to_string(eml_path).unwrap_or_else(|_| panic!("Failed to read {}", eml_path));
        let key_der = pem::parse(fs::read(key_path).unwrap_or_else(|_| panic!("Failed to read {}", key_path)))
            .expect("Failed to parse PEM")
            .into_contents();
        let cert_der = load_cert_der(key_path);
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_ecdh() {
        ec_decrypt_test("tests/general/test_encrypted_ecdh.eml", "tests/keys/test_p256.key");
        ec_decrypt_test("tests/general/test_encrypted_ecdh_p384.eml", "tests/keys/test_p384.key");
        ec_decrypt_test("tests/general/test_encrypted_ecdh_p521.eml", "tests/keys/test_p521.key");
    }

    #[test]
    fn test_decrypt_multi_recipient_with_rsa() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_recipient.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
        assert_eq!(result.encryption_info.as_ref().unwrap().recipients.len(), 2);
    }

    #[test]
    fn test_decrypt_multi_recipient_with_ec() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_recipient.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
        assert_eq!(result.encryption_info.as_ref().unwrap().recipients.len(), 2);
    }

    #[test]
    fn test_decrypt_ecdh_recipient_info() {
        let eml = fs::read_to_string("tests/general/test_encrypted_ecdh.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        let enc = result.encryption_info.as_ref().expect("encryption_info");
        assert_eq!(enc.recipients.len(), 1);
        assert!(
            enc.recipients[0].key_encryption_algorithm.starts_with("dhSinglePass-"),
            "Expected dhSinglePass-*, got: {}",
            enc.recipients[0].key_encryption_algorithm
        );
        assert!(enc.recipients[0].issuer.contains("Kalle"), "Expected issuer DN, got: {}", enc.recipients[0].issuer);
        assert!(!enc.recipients[0].serial_number.is_empty(), "Expected serial number");
    }

    #[test]
    fn test_signed_then_encrypted() {
        let eml = fs::read_to_string("tests/general/test_signed_then_encrypted.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            nested_trust(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(result.failures.is_empty(), "Unexpected failures: {:?}", result.failures);
        assert!(result.encryption_info.is_some());
        // The decrypted SignedData layer has no From header of its own; the outer
        // message's From is used for its verification.
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].signature_valid);
        assert_eq!(result.from_address.as_deref(), Some("kalle@naide.ee"));
        let content = String::from_utf8(result.signed_content.unwrap()).unwrap();
        assert!(content.contains("signed then encrypted"));
    }

    #[test]
    fn test_double_encrypted_signed() {
        // E > S > E > S > Data - two layers of encrypt+sign
        let eml = fs::read_to_string("tests/general/test_double_encrypted_signed.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            nested_trust(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(result.failures.is_empty(), "Unexpected failures: {:?}", result.failures);
        assert!(result.encryption_info.is_some());
        // Both signed layers verify, each against the outer message's From.
        assert_eq!(result.signers.len(), 2);
        assert!(result.signers.iter().all(|s| s.signature_valid));
        let content = String::from_utf8(result.signed_content.unwrap()).unwrap();
        assert!(content.contains("innermost content"));
    }

    #[test]
    fn test_nesting_exceeds_max_depth() {
        // 5x (sign+encrypt) = 10 CMS layers, exceeds MAX_DECRYPT_DEPTH
        let eml = fs::read_to_string("tests/general/test_10_layers.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(!result.failures.is_empty());
        let has_depth_error = result.failures.iter().any(|f| match f {
            SmimeError::DecryptionFailed { err } => err.contains("nesting depth"),
            _ => false,
        });
        assert!(has_depth_error, "Expected nesting depth error, got: {:?}", result.failures);
    }

    #[test]
    fn test_signed_then_bad_envelope_reports_error() {
        // Signed message wrapping bogus enveloped-data - the S>E path should
        // report a parse error instead of silently returning encrypted content
        let eml = fs::read_to_string("tests/general/test_signed_bad_envelope.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(!result.failures.is_empty(), "Expected a failure for bogus inner envelope");
    }

    #[test]
    fn test_decrypt_ecdh_with_rsa_key() {
        let eml = fs::read_to_string("tests/general/test_encrypted_ecdh.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(!result.failures.is_empty(), "Expected failure when using RSA key for ECDH");
    }

    #[test]
    fn test_decrypt_rsa_with_ec_key() {
        let eml = fs::read_to_string("tests/general/test_encrypted_rsa_aes256.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(!result.failures.is_empty(), "Expected failure when using EC key for RSA");
    }

    // tests/nested/ - real-world messages from Comarch test environment
    fn nested_key_der() -> Vec<u8> {
        let p12 = fs::read("tests/nested/certificate.p12").expect("Failed to read p12");
        smime::pkcs12_utils::extract_private_key_from_p12(&p12, "1234567890").expect("Failed to extract key from p12")
    }

    #[test]
    fn test_nested_encrypted_signed() {
        let eml = fs::read_to_string("tests/nested/message.eml").expect("Failed to read file");
        let cert_der = pem::parse(fs::read("tests/nested/certificate.pem").expect("Failed to read cert"))
            .expect("Failed to parse cert PEM")
            .into_contents();
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug, TrustStore::Builtin].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &nested_key_der(), recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        let enc = result.encryption_info.as_ref().expect("encryption_info should be set");
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "128-bit");
        assert_eq!(enc.recipients.len(), 2);
        assert_eq!(result.from_address.as_deref(), Some("dagmara.pasek@sandbox.comarch.com"));
        let expected = fs::read("tests/nested/message_decrypted_content.eml").expect("Failed to read expected content");
        assert_eq!(result.signed_content.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn test_nested_encrypted_without_key() {
        // Same encrypted message, but without providing a key for decryption
        let eml = fs::read_to_string("tests/nested/message.eml").expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug, TrustStore::Builtin].into());
        println!("Result: {:#?}", result);

        assert!(!result.failures.is_empty());
        assert!(result.signed_content.is_none());
        assert!(result.encryption_info.is_none());
    }

    #[test]
    fn test_nested_gmail_cse_signed() {
        // Gmail CSE signed message (signed-data, not encrypted)
        let eml = fs::read_to_string("tests/nested/message_gmail_cse_signed.eml").expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug, TrustStore::Builtin].into());
        println!("Result: {:#?}", result);

        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        assert_eq!(result.signers.len(), 1);
        assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
        assert!(result.signers[0].validation_details.checks.message_digest_matches_content);
        assert_eq!(result.from_address.as_deref(), Some("wojciech.lebiest@comarch.com"));
    }

    fn x25519_decrypt_test(eml_path: &str, expected_kdf: &str) {
        let eml = fs::read_to_string(eml_path).unwrap_or_else(|_| panic!("Failed to read {}", eml_path));
        let key_der = pem::parse(fs::read("tests/keys/test_x25519.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_x25519.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "deterministic X25519 test");
        let enc =
            result.encryption_info.as_ref().unwrap_or_else(|| panic!("{}: no encryption_info; failures: {:?}", eml_path, result.failures));
        assert_eq!(enc.cipher, "AES-CBC");
        assert_eq!(enc.key_size, "128-bit");
        assert!(
            enc.recipients[0].key_encryption_algorithm.contains(expected_kdf),
            "{}: expected KDF '{}', got '{}'",
            eml_path,
            expected_kdf,
            enc.recipients[0].key_encryption_algorithm
        );
    }

    #[test]
    fn test_decrypt_x25519() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519.eml", "stdDH-sha256kdf");
    }

    #[test]
    fn test_decrypt_x25519_hkdf256() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519_hkdf256.eml", "hkdf-sha256");
    }

    #[test]
    fn test_decrypt_x25519_hkdf384() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519_hkdf384.eml", "hkdf-sha384");
    }

    #[test]
    fn test_decrypt_x25519_hkdf512() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519_hkdf512.eml", "hkdf-sha512");
    }

    #[test]
    fn test_decrypt_x25519_x963_sha384() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519_x963_sha384.eml", "stdDH-sha384kdf");
    }

    #[test]
    fn test_decrypt_x25519_x963_sha512() {
        x25519_decrypt_test("tests/general/test_encrypted_x25519_x963_sha512.eml", "stdDH-sha512kdf");
    }

    #[test]
    fn test_decrypt_x25519_with_rsa_key() {
        let eml = fs::read_to_string("tests/general/test_encrypted_x25519.eml").expect("read");
        let rsa_key = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &rsa_key, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert!(!result.failures.is_empty(), "Should fail with wrong key type");
    }

    #[test]
    fn test_nested_signed_encrypted() {
        let eml = fs::read_to_string("tests/nested/message_encrypted.eml").expect("Failed to read file");
        let cert_der = pem::parse(fs::read("tests/nested/certificate.pem").expect("Failed to read cert"))
            .expect("Failed to parse cert PEM")
            .into_contents();
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug, TrustStore::Builtin].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &nested_key_der(), recipient_cert_der: &cert_der, ..Default::default() },
        );
        println!("Result: {:#?}", result);

        assert_eq!(result.signing_system, SigningSystem::MIMEPartSMIME);
        // The message is signed twice (sign over sign inside the envelope); both
        // signatures are verified, the inner one against the outer message's From.
        assert_eq!(result.signers.len(), 2);
        for signer in &result.signers {
            assert!(signer.validation_details.checks.signature_matches_signed_data);
            assert!(signer.validation_details.checks.message_digest_matches_content);
        }
        assert_eq!(result.from_address.as_deref(), Some("dagmara.pasek@sandbox.comarch.com"));
        let expected = fs::read("tests/nested/message_decrypted_content.eml").expect("Failed to read expected content");
        assert_eq!(result.signed_content.as_deref(), Some(expected.as_slice()));
        assert!(result.encryption_info.is_some());
    }

    #[test]
    fn test_decrypt_pwri() {
        let eml = fs::read_to_string("tests/general/test_encrypted_pwri.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { password: Some("zone.eu"), ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_pwri_wrong_password() {
        let eml = fs::read_to_string("tests/general/test_encrypted_pwri.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { password: Some("wrong"), ..Default::default() },
        );
        assert!(!result.failures.is_empty(), "Should fail with wrong password");
    }

    #[test]
    fn test_decrypt_pwri_no_password() {
        let eml = fs::read_to_string("tests/general/test_encrypted_pwri.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys::default(),
        );
        assert!(!result.failures.is_empty(), "Should fail without password");
    }

    #[test]
    fn test_decrypt_aes_128_gcm() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_gcm128.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-GCM");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "128-bit");
    }

    #[test]
    fn test_decrypt_aes_256_gcm() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_gcm256.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-GCM");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "256-bit");
    }

    #[cfg(feature = "decrypt-ccm")]
    #[test]
    fn test_decrypt_aes_128_ccm() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_ccm128.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "AES-CCM AuthEnvelopedData test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CCM");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "128-bit");
    }

    #[cfg(feature = "decrypt-ccm")]
    #[test]
    fn test_decrypt_aes_256_ccm() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_ccm256.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "AES-CCM AuthEnvelopedData test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CCM");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "256-bit");
    }

    #[test]
    fn test_decrypt_ecdh_wrap256() {
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_ecdh_wrap256.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "256-bit");
    }

    #[test]
    fn test_decrypt_aes_192_gcm() {
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_gcm192.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-GCM");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "192-bit");
    }

    #[test]
    fn test_decrypt_gcm256_ecdh() {
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_gcm256_ecdh.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-GCM");
    }

    #[test]
    fn test_decrypt_ecdh_aes128() {
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_ecdh_aes128.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "128-bit");
    }

    #[test]
    fn test_decrypt_ecdh_wrap192() {
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let eml = fs::read_to_string("tests/general/test_encrypted_ecdh_wrap192.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_kekri() {
        let kek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let eml = fs::read_to_string("tests/general/test_encrypted_kekri.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { kek: Some(&kek), ..Default::default() },
        );
        assert_decrypted_ok(&result, "OpenSSL-generated test fixture");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    // Multi-recipient-type tests: all 4 RecipientInfo types in one EnvelopedData

    #[test]
    fn test_decrypt_multi_type_all_with_rsa() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
        assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "256-bit");
    }

    #[test]
    fn test_decrypt_multi_type_all_with_p256() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_p256.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_p256.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_all_with_x25519() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_x25519.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_x25519.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_all_with_kek() {
        let kek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { kek: Some(&kek), ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_all_with_password() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { password: Some("zone.eu"), ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_all_recipient_count() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        let enc = result.encryption_info.as_ref().expect("encryption_info");
        assert!(enc.recipients.len() >= 3, "Expected at least 3 summarized recipients, got {}", enc.recipients.len());
    }

    // Multi-recipient-type: RSA + PWRI

    #[test]
    fn test_decrypt_multi_type_rsa_pwri_with_rsa() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_rsa_pwri.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_rsa_pwri_with_password() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_rsa_pwri.eml").expect("read");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { password: Some("zone.eu"), ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-CBC");
    }

    #[test]
    fn test_decrypt_multi_type_rsa_pwri_recipient_count() {
        let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_rsa_pwri.eml").expect("read");
        let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
        let cert_der = load_cert_der("tests/keys/test_rsa.key");
        let result = smime::decrypt_and_verify_smime_from_eml_detailed(
            eml,
            vec![TrustStore::Debug].into(),
            &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
        );
        assert_decrypted_ok(&result, "Multi-recipient-type test");
        let enc = result.encryption_info.as_ref().expect("encryption_info");
        assert_eq!(enc.recipients.len(), 1, "Expected 1 summarized KTRI recipient, got {}", enc.recipients.len());
    }
}
