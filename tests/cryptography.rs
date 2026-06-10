use smime::errors::SmimeError;
use smime::{TrustStore, verify_smime_from_eml_detailed};
use std::fs;

// Minimal 1024-bit RSA public key in SPKI DER format for unit tests
const RSA_TEST_SPKI_DER: [u8; 162] = [
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc1, 0xcf, 0xdd, 0x8d, 0xde, 0x2d, 0xe3, 0x50, 0x72, 0x6d, 0x5d, 0x3e, 0x60, 0xdf, 0xd5,
    0x4c, 0xe3, 0xdf, 0x9a, 0xd8, 0x6b, 0x3f, 0xed, 0x78, 0x26, 0xaf, 0x04, 0xe6, 0xb2, 0xa1, 0x92, 0x24, 0x71, 0x25, 0x92, 0xb8, 0xe7,
    0x96, 0x4f, 0x6c, 0x7d, 0x40, 0xf4, 0xde, 0x12, 0xcd, 0x14, 0xc8, 0xb4, 0x12, 0xfd, 0xfc, 0x91, 0x7b, 0x5a, 0xd9, 0x23, 0x54, 0x20,
    0xc2, 0xa9, 0x2c, 0x57, 0xe9, 0x10, 0x80, 0xd3, 0xa4, 0x34, 0x28, 0x7a, 0xaf, 0x56, 0x4a, 0x9d, 0x6d, 0x17, 0x00, 0x99, 0xff, 0x8c,
    0x2a, 0xeb, 0x53, 0x48, 0xf2, 0x40, 0x21, 0xe0, 0xd5, 0x8d, 0xcd, 0x2a, 0x8c, 0x62, 0x2d, 0x20, 0xf1, 0x40, 0xa7, 0x24, 0x14, 0xd9,
    0x1e, 0x51, 0x8a, 0x3d, 0x30, 0x74, 0x30, 0x03, 0xaf, 0x4f, 0x1d, 0x78, 0xb7, 0x0f, 0x24, 0x01, 0xa9, 0x97, 0xdc, 0x9f, 0x52, 0x6b,
    0xb4, 0xbe, 0x83, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// Minimal P-256 public key in SPKI DER format for unit tests
const P256_TEST_SPKI_DER: [u8; 91] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04, 0x5d, 0xaa, 0x32, 0xbf, 0x42, 0xac, 0x2e, 0x30, 0x7d, 0x33, 0x45, 0x35, 0x7c, 0x8d, 0x03, 0xf2, 0x94,
    0xb5, 0x62, 0x4c, 0x26, 0x01, 0x8d, 0x95, 0x16, 0xcd, 0x6d, 0xfe, 0x42, 0xc2, 0xad, 0x10, 0x7f, 0x26, 0x0f, 0x2c, 0x0c, 0x9b, 0x4a,
    0x16, 0x11, 0xf7, 0x26, 0xa2, 0xa1, 0x5f, 0x9b, 0x3d, 0xd6, 0x27, 0x50, 0x55, 0x2d, 0x86, 0xd8, 0x47, 0x82, 0xc5, 0xa0, 0xd9, 0x59,
    0xe3, 0x20, 0x46,
];

// Minimal P-384 public key in SPKI DER format for unit tests
const P384_TEST_SPKI_DER: [u8; 120] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62,
    0x00, 0x04, 0x7f, 0x93, 0xbc, 0x7f, 0xb0, 0x33, 0x7e, 0x99, 0x38, 0xda, 0x2b, 0x46, 0xa6, 0xca, 0xc1, 0xb7, 0x4a, 0x13, 0x32, 0x66,
    0x9d, 0x64, 0xb0, 0xa9, 0x57, 0x93, 0x9c, 0x0e, 0x4e, 0x0d, 0xb2, 0x6e, 0x05, 0x63, 0x3f, 0x10, 0xdb, 0x3a, 0x0b, 0x91, 0x2c, 0xb2,
    0x64, 0x48, 0xc8, 0x9b, 0x8b, 0x70, 0x58, 0xdb, 0x3f, 0x3b, 0xbc, 0x3a, 0x5d, 0x53, 0xbc, 0x81, 0xf3, 0x72, 0x27, 0x38, 0xfa, 0x4a,
    0x90, 0xad, 0x29, 0xac, 0x55, 0x73, 0xd0, 0xd5, 0x7c, 0x94, 0x19, 0x91, 0xb5, 0x00, 0x60, 0x42, 0xae, 0xd4, 0x57, 0x64, 0xa1, 0x66,
    0x1d, 0x20, 0xbb, 0xee, 0x55, 0x0f, 0xa2, 0x39, 0x96, 0xf5,
];

// Minimal P-521 public key in SPKI DER format for unit tests
const P521_TEST_SPKI_DER: [u8; 158] = [
    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03,
    0x81, 0x86, 0x00, 0x04, 0x00, 0xb8, 0xb2, 0x9a, 0x14, 0x8f, 0xca, 0x4f, 0xa7, 0x88, 0xe7, 0x30, 0x6f, 0xe1, 0xb1, 0xe6, 0xdc, 0x98,
    0xab, 0x8f, 0x37, 0xdd, 0x94, 0x12, 0x80, 0x56, 0xc8, 0x53, 0xc1, 0x8d, 0x54, 0x10, 0x73, 0x3d, 0x6c, 0x31, 0x7b, 0x5c, 0x62, 0xb9,
    0x00, 0x8d, 0x97, 0x54, 0x5d, 0x0c, 0x7d, 0x13, 0xe1, 0x9c, 0x09, 0xe3, 0x76, 0xa7, 0xff, 0xcc, 0x15, 0xc1, 0xc3, 0xe7, 0x5d, 0xdc,
    0x7c, 0xd3, 0x96, 0xba, 0x00, 0x67, 0x3a, 0xcf, 0x9e, 0x42, 0x0f, 0xf3, 0x49, 0x89, 0xc0, 0x68, 0xe5, 0x93, 0xaf, 0x1f, 0xad, 0x51,
    0xb9, 0x18, 0x16, 0xc4, 0x93, 0x6d, 0xd5, 0xec, 0x94, 0x17, 0x82, 0x78, 0xb6, 0x91, 0x4a, 0x65, 0xc2, 0xc7, 0xe3, 0xfe, 0xf1, 0x45,
    0x77, 0xa3, 0x83, 0xc4, 0x68, 0xb0, 0xd2, 0x0f, 0x0f, 0xbe, 0xb0, 0x5b, 0x9a, 0xb2, 0xc3, 0x06, 0x55, 0x79, 0xfc, 0x74, 0x70, 0x27,
    0xeb, 0x8a, 0x96, 0x3f,
];

#[test]
fn test_hash_algorithm_rejection() {
    use smime::cms_utils::verify_signature;
    use smime::cryptography_x509_verify::sign::{HashType, SignatureParameters};

    let dummy_data = b"data";
    let rsa_dummy_sig = &[0u8; 128];
    let ecdsa_dummy_sig: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let rsa_key = smime::AnyPublicKey::RSA { algorithm: smime::cryptography_x509::oid::RSA_OID, spki_der: RSA_TEST_SPKI_DER.to_vec() };
    let p256_key = smime::AnyPublicKey::P256 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P256_TEST_SPKI_DER.to_vec() };

    // Weak/unsupported hashes must be rejected with "Unsupported" error
    for hash in [HashType::SHA1, HashType::SHA224, HashType::SHA3_224, HashType::SHAKE128, HashType::SHAKE256] {
        let err = verify_signature(&rsa_key, &SignatureParameters::RSAPKCS1v15 { hash: hash.clone() }, rsa_dummy_sig, dummy_data)
            .expect_err(&format!("PKCS1v15+{hash:?} should be rejected"));
        assert!(err.to_string().contains("Unsupported"), "PKCS1v15+{hash:?}: expected 'Unsupported', got: {err}");

        let err = verify_signature(&rsa_key, &SignatureParameters::RSAPSS { hash: hash.clone() }, rsa_dummy_sig, dummy_data)
            .expect_err(&format!("PSS+{hash:?} should be rejected"));
        assert!(err.to_string().contains("Unsupported"), "PSS+{hash:?}: expected 'Unsupported', got: {err}");

        let err = verify_signature(&p256_key, &SignatureParameters::ECDSA { hash: hash.clone() }, ecdsa_dummy_sig, dummy_data)
            .expect_err(&format!("ECDSA+{hash:?} should be rejected"));
        assert!(err.to_string().contains("Unsupported"), "ECDSA+{hash:?}: expected 'Unsupported', got: {err}");
    }
}

#[test]
fn test_hash_algorithm_accepted() {
    use smime::cms_utils::verify_signature;
    use smime::cryptography_x509_verify::sign::{HashType, SignatureParameters};

    let dummy_data = b"data";
    let rsa_dummy_sig = &[0u8; 128];
    let ecdsa_dummy_sig: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let rsa_key = smime::AnyPublicKey::RSA { algorithm: smime::cryptography_x509::oid::RSA_OID, spki_der: RSA_TEST_SPKI_DER.to_vec() };

    // All supported hashes must NOT be rejected as "Unsupported" for RSA
    for hash in [HashType::SHA256, HashType::SHA384, HashType::SHA512, HashType::SHA3_256, HashType::SHA3_384, HashType::SHA3_512] {
        let err = verify_signature(&rsa_key, &SignatureParameters::RSAPKCS1v15 { hash: hash.clone() }, rsa_dummy_sig, dummy_data)
            .expect_err(&format!("PKCS1v15+{hash:?} should fail (bad sig)"));
        assert!(!err.to_string().contains("Unsupported"), "PKCS1v15+{hash:?}: unexpected 'Unsupported': {err}");

        let err = verify_signature(&rsa_key, &SignatureParameters::RSAPSS { hash: hash.clone() }, rsa_dummy_sig, dummy_data)
            .expect_err(&format!("PSS+{hash:?} should fail (bad sig)"));
        assert!(!err.to_string().contains("Unsupported"), "PSS+{hash:?}: unexpected 'Unsupported': {err}");
    }

    // All supported hashes must NOT be rejected as "Unsupported" for any ECDSA curve
    for (key, label) in [
        (smime::AnyPublicKey::P256 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P256_TEST_SPKI_DER.to_vec() }, "P-256"),
        (smime::AnyPublicKey::P384 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P384_TEST_SPKI_DER.to_vec() }, "P-384"),
        (smime::AnyPublicKey::P521 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P521_TEST_SPKI_DER.to_vec() }, "P-521"),
    ] {
        for hash in [HashType::SHA256, HashType::SHA384, HashType::SHA512, HashType::SHA3_256, HashType::SHA3_384, HashType::SHA3_512] {
            let err = verify_signature(&key, &SignatureParameters::ECDSA { hash: hash.clone() }, ecdsa_dummy_sig, dummy_data)
                .expect_err(&format!("{label}+{hash:?} should fail (bad sig)"));
            assert!(!err.to_string().contains("Unsupported"), "{label}+{hash:?}: unexpected 'Unsupported': {err}");
        }
    }
}

#[test]
fn test_hash_algorithm_warnings() {
    use smime::cms_utils::check_hash_recommended;
    use smime::cryptography_x509_verify::sign::{HashType, SignatureParameters};

    let p256_key = smime::AnyPublicKey::P256 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P256_TEST_SPKI_DER.to_vec() };
    let p384_key = smime::AnyPublicKey::P384 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P384_TEST_SPKI_DER.to_vec() };
    let p521_key = smime::AnyPublicKey::P521 { algorithm: smime::cryptography_x509::oid::EC_OID, spki_der: P521_TEST_SPKI_DER.to_vec() };
    let rsa_key = smime::AnyPublicKey::RSA { algorithm: smime::cryptography_x509::oid::RSA_OID, spki_der: RSA_TEST_SPKI_DER.to_vec() };

    // Recommended combinations: no error
    assert!(check_hash_recommended(&p256_key, &SignatureParameters::ECDSA { hash: HashType::SHA256 }).is_ok());
    assert!(check_hash_recommended(&p256_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_256 }).is_ok());
    assert!(check_hash_recommended(&p384_key, &SignatureParameters::ECDSA { hash: HashType::SHA384 }).is_ok());
    assert!(check_hash_recommended(&p384_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_384 }).is_ok());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA512 }).is_ok());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_512 }).is_ok());

    // Weaker-than-recommended: error
    assert!(check_hash_recommended(&p384_key, &SignatureParameters::ECDSA { hash: HashType::SHA256 }).is_err());
    assert!(check_hash_recommended(&p384_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_256 }).is_err());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA256 }).is_err());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA384 }).is_err());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_256 }).is_err());
    assert!(check_hash_recommended(&p521_key, &SignatureParameters::ECDSA { hash: HashType::SHA3_384 }).is_err());

    // RSA: no recommendation errors (any supported hash is fine)
    assert!(check_hash_recommended(&rsa_key, &SignatureParameters::RSAPKCS1v15 { hash: HashType::SHA256 }).is_ok());
    assert!(check_hash_recommended(&rsa_key, &SignatureParameters::RSAPSS { hash: HashType::SHA256 }).is_ok());
}

// Fixtures below are written by our own `create-cms sign`
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
fn test_ed25519_sha256_digest() {
    let eml = fs::read_to_string("tests/general/ed25519-sha256-digest.eml").expect("Failed to read eml file");
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
    println!("Result: {:#?}", result);
    // Signature itself is valid; the RFC 8419 §3.1 digest rule must still be flagged
    assert_eq!(result.signers.len(), 1);
    assert!(result.signers[0].validation_details.checks.signature_matches_signed_data);
    assert!(
        result.failures.iter().any(|f| matches!(f, SmimeError::DigestAlgorithmWarning { detail, .. } if detail.contains("SHA512"))),
        "expected Ed25519 digest algorithm failure, got: {:?}",
        result.failures
    );
}

#[test]
fn test_no_message_digest_attr() {
    let eml = fs::read_to_string("tests/general/no-message-digest-attr.eml").expect("read");
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
    assert!(
        result.failures.iter().any(|f| matches!(f, SmimeError::DigestVerify { err } if err.contains("message-digest attribute missing"))),
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
    assert!(result.signed_content.as_ref().is_some_and(|c| c.starts_with(b"Content-Type: text/plain\r\n\r\nNo authenticated attributes")));
}
