#![cfg(feature = "decrypt")]

use smime::TrustStore;
use smime::errors::SmimeError;
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
fn test_wrong_content_type_rejected() {
    use smime::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters, Asn1ReadableOrWritable};
    use smime::cryptography_x509::pkcs7::*;

    let iv: [u8; 16] = [0u8; 16];
    let dummy_ct = [0u8; 16];
    let wrong_oid = PKCS7_SIGNED_DATA_OID;

    let enveloped = EnvelopedData {
        version: 0,
        originator_info: None,
        recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&[])),
        encrypted_content_info: EncryptedContentInfo {
            content_type: wrong_oid,
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Aes128Cbc(iv),
            },
            encrypted_content: Some(&dummy_ct),
        },
        unprotected_attrs: None,
    };

    let der = asn1::write_single(&enveloped).unwrap();
    let parsed: EnvelopedData = asn1::parse_single(&der).unwrap();
    let dummy_key = [0u8; 32];
    let err = smime::decrypt::decrypt_enveloped_data(
        &parsed,
        &smime::decrypt::DecryptionKeys { private_key_der: &dummy_key, ..Default::default() },
    )
    .unwrap_err();
    assert!(
        matches!(err, SmimeError::UnsupportedContentEncryptionAlg { ref alg } if alg.contains("contentType")),
        "expected contentType error, got: {:?}",
        err,
    );
}

#[test]
fn test_oaep_non_mgf1_mask_gen_rejected() {
    use smime::cryptography_x509::common::{
        AlgorithmIdentifier, AlgorithmParameters, Asn1ReadableOrWritable, MaskGenAlgorithm, PSS_SHA256_HASH_ALG, RsaOaepParameters,
    };
    use smime::cryptography_x509::pkcs7::*;

    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_rsa.key");
    let cert = asn1::parse_single::<smime::cryptography_x509::certificate::Certificate>(&cert_der).expect("cert");

    // RFC 3560 §3 requires MGF1; any other maskGenFunc OID must be rejected.
    let oaep = RsaOaepParameters {
        hash_algorithm: PSS_SHA256_HASH_ALG,
        mask_gen_algorithm: MaskGenAlgorithm { oid: asn1::oid!(1, 2, 840, 113549, 1, 1, 99), params: PSS_SHA256_HASH_ALG },
        p_source_func: None,
    };
    let dummy_key = [0u8; 256];
    let recipients = [RecipientInfo::KeyTransRecipientInfo(KeyTransRecipientInfo {
        version: 0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_cert.issuer.clone(),
            serial_number: cert.tbs_cert.serial,
        }),
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaesOaep(Box::new(oaep)),
        },
        encrypted_key: &dummy_key,
    })];
    let iv = [0u8; 16];
    let dummy_ct = [0u8; 16];
    let enveloped = EnvelopedData {
        version: 0,
        originator_info: None,
        recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&recipients)),
        encrypted_content_info: EncryptedContentInfo {
            content_type: PKCS7_DATA_OID,
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Aes128Cbc(iv),
            },
            encrypted_content: Some(&dummy_ct),
        },
        unprotected_attrs: None,
    };

    let der = asn1::write_single(&enveloped).unwrap();
    let parsed: EnvelopedData = asn1::parse_single(&der).unwrap();
    let err = smime::decrypt::decrypt_enveloped_data(
        &parsed,
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    )
    .unwrap_err();
    assert!(
        matches!(err, SmimeError::UnsupportedKeyEncryptionAlg { ref alg } if alg.contains("maskGenFunc")),
        "expected maskGenFunc error, got: {:?}",
        err,
    );
}

#[test]
#[cfg(feature = "encrypt")]
fn test_oaep_mgf1_sha1_with_sha256_hash_decrypts() {
    use rsa::pkcs8::DecodePrivateKey as _;
    use smime::cryptography_x509::common::{
        AlgorithmIdentifier, AlgorithmParameters, Asn1ReadableOrWritable, PSS_SHA1_MASK_GEN_ALG, PSS_SHA256_HASH_ALG, RsaOaepParameters,
    };
    use smime::cryptography_x509::pkcs7::*;

    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_rsa.key");
    let cert = asn1::parse_single::<smime::cryptography_x509::certificate::Certificate>(&cert_der).expect("cert");

    // RFC 8017 A.2.1: hashFunc and the MGF1 hash are independent; SHA-256 with the
    // default mgf1SHA1 is legal (and what Java's OAEPWithSHA-256AndMGF1Padding emits).
    let plaintext = b"mixed OAEP digests";
    let cek = [0x42u8; 16];
    let iv = [7u8; 16];
    let encrypted_content = smime::encrypt::encrypt_aes_cbc(&cek, &iv, plaintext);

    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).expect("rsa key");
    let mut rng = rsa::rand_core::UnwrapErr(getrandom::SysRng);
    let encrypted_key = private_key
        .to_public_key()
        .encrypt(&mut rng, rsa::Oaep::<sha2::Sha256, sha1::Sha1>::new_with_mgf_hash(), &cek)
        .expect("OAEP encrypt");

    let oaep = RsaOaepParameters { hash_algorithm: PSS_SHA256_HASH_ALG, mask_gen_algorithm: PSS_SHA1_MASK_GEN_ALG, p_source_func: None };
    let recipients = [RecipientInfo::KeyTransRecipientInfo(KeyTransRecipientInfo {
        version: 0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_cert.issuer.clone(),
            serial_number: cert.tbs_cert.serial,
        }),
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::RsaesOaep(Box::new(oaep)),
        },
        encrypted_key: &encrypted_key,
    })];
    let enveloped = EnvelopedData {
        version: 0,
        originator_info: None,
        recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&recipients)),
        encrypted_content_info: EncryptedContentInfo {
            content_type: PKCS7_DATA_OID,
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Aes128Cbc(iv),
            },
            encrypted_content: Some(&encrypted_content),
        },
        unprotected_attrs: None,
    };

    let der = asn1::write_single(&enveloped).unwrap();
    let parsed: EnvelopedData = asn1::parse_single(&der).unwrap();
    let (content, warnings) = smime::decrypt::decrypt_enveloped_data(
        &parsed,
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    )
    .expect("mixed-digest OAEP should decrypt");
    assert_eq!(content.as_deref(), Some(plaintext.as_slice()));
    assert!(
        warnings.iter().any(|w| matches!(w, SmimeError::WeakKeyEncryptionAlg { alg } if alg.contains("SHA-1"))),
        "expected SHA-1 weakness warning, got: {:?}",
        warnings,
    );
}

// Fixtures below are written by our own `create-cms` (nested, additional, multi-recipient)

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
    let has_parse_error = result.failures.iter().any(|f| matches!(f, SmimeError::ParsePkcs7Msg { .. }));
    assert!(has_parse_error, "Expected ParsePkcs7Msg for bogus inner envelope, got: {:?}", result.failures);
    assert!(result.signed_content.is_none(), "Encrypted content must not be returned as signed_content");
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
fn test_decrypt_x25519_ukm() {
    x25519_decrypt_test("tests/general/test_encrypted_x25519_ukm.eml", "stdDH-sha256kdf");
}

#[test]
fn test_decrypt_x25519_hkdf256_ukm() {
    x25519_decrypt_test("tests/general/test_encrypted_x25519_hkdf256_ukm.eml", "hkdf-sha256");
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
    let has_key_error = result.failures.iter().any(|f| matches!(f, SmimeError::PrivateKeyParseFailed { .. }));
    assert!(has_key_error, "Expected PrivateKeyParseFailed when using RSA key for X25519, got: {:?}", result.failures);
}

#[test]
fn test_decrypt_x25519_wrong_originator_algorithm() {
    use base64::prelude::*;
    let eml = fs::read_to_string("tests/general/test_encrypted_x25519.eml").expect("read");
    let (headers, body) = eml.split_once("\r\n\r\n").expect("eml body");
    let der = BASE64_STANDARD.decode(body.replace(['\r', '\n'], "")).expect("base64");
    // Swap the originatorKey algorithm OID from id-X25519 (1.3.101.110) to id-X448 (1.3.101.111)
    let x25519_oid_der = [0x06, 0x03, 0x2b, 0x65, 0x6e];
    let positions: Vec<usize> =
        der.windows(x25519_oid_der.len()).enumerate().filter(|(_, w)| *w == x25519_oid_der).map(|(i, _)| i).collect();
    assert_eq!(positions.len(), 1, "expected exactly one id-X25519 OID in fixture");
    let mut tampered = der;
    tampered[positions[0] + 4] = 0x6f;
    let tampered_eml = format!("{}\r\n\r\n{}", headers, BASE64_STANDARD.encode(&tampered));

    let key_der = pem::parse(fs::read("tests/keys/test_x25519.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_x25519.key");
    let result = smime::decrypt_and_verify_smime_from_eml_detailed(
        tampered_eml,
        vec![TrustStore::Debug].into(),
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    );
    let has_originator_error =
        result.failures.iter().any(|f| matches!(f, SmimeError::DecryptionFailed { err } if err.contains("is not id-X25519")));
    assert!(has_originator_error, "Expected originatorKey algorithm mismatch error, got: {:?}", result.failures);
}

#[test]
fn test_decrypt_x448_key_rejected() {
    let eml = fs::read_to_string("tests/general/test_encrypted_x25519.eml").expect("read");
    // Minimal PKCS#8 PrivateKeyInfo with the X448 OID (1.3.101.111); the key bytes are
    // never used because the algorithm is rejected before any key agreement.
    let mut x448_key = vec![0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38];
    x448_key.extend_from_slice(&[0u8; 56]);
    let cert_der = load_cert_der("tests/keys/test_x25519.key");
    let result = smime::decrypt_and_verify_smime_from_eml_detailed(
        eml,
        vec![TrustStore::Debug].into(),
        &smime::decrypt::DecryptionKeys { private_key_der: &x448_key, recipient_cert_der: &cert_der, ..Default::default() },
    );
    let has_x448_error =
        result.failures.iter().any(|f| matches!(f, SmimeError::UnsupportedKeyEncryptionAlg { alg } if alg.contains("X448")));
    assert!(has_x448_error, "Expected explicit X448 rejection, got: {:?}", result.failures);
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
fn test_decrypt_aes_256_gcm_icvlen12() {
    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_rsa.key");
    let eml = fs::read_to_string("tests/general/test_encrypted_gcm_icvlen12.eml").expect("read");
    let result = smime::decrypt_and_verify_smime_from_eml_detailed(
        eml,
        vec![TrustStore::Debug].into(),
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    );
    assert_decrypted_ok(&result, "AES-GCM ICVlen 12 test");
    assert_eq!(result.encryption_info.as_ref().unwrap().cipher, "AES-GCM");
    assert_eq!(result.encryption_info.as_ref().unwrap().key_size, "256-bit");
}

#[test]
fn test_recipient_info_version_mismatch_recorded() {
    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_rsa.key");
    let eml = fs::read_to_string("tests/general/test_encrypted_ktri_bad_version.eml").expect("read");
    let result = smime::decrypt_and_verify_smime_from_eml_detailed(
        eml,
        vec![TrustStore::Debug].into(),
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    );
    assert_decrypted_ok(&result, "Multi-recipient-type test");
    let has_mismatch = result.failures.iter().any(|f| {
        matches!(f, SmimeError::CmsVersionMismatch { structure, expected: 0, actual: 2, idx: Some(0) } if structure == "KeyTransRecipientInfo")
    });
    assert!(has_mismatch, "expected KeyTransRecipientInfo version mismatch, got: {:?}", result.failures);
}

#[test]
fn test_recipient_info_versions_valid_no_mismatch() {
    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").expect("read")).expect("pem").into_contents();
    let cert_der = load_cert_der("tests/keys/test_rsa.key");
    let eml = fs::read_to_string("tests/general/test_encrypted_multi_type_all.eml").expect("read");
    let result = smime::decrypt_and_verify_smime_from_eml_detailed(
        eml,
        vec![TrustStore::Debug].into(),
        &smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() },
    );
    assert_decrypted_ok(&result, "Multi-recipient-type test");
    let mismatches: Vec<_> = result.failures.iter().filter(|f| matches!(f, SmimeError::CmsVersionMismatch { .. })).collect();
    assert!(mismatches.is_empty(), "unexpected version mismatches: {:?}", mismatches);
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
#[cfg(feature = "decrypt-kek")]
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
#[cfg(feature = "decrypt-pwri")]
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
#[cfg(feature = "decrypt-pwri")]
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
