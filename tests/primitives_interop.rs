#![cfg(feature = "decrypt")]

fn assert_extracts_key(path: &str, password: &str) {
    let p12 = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
    let key_der = smime::pkcs12_utils::extract_private_key_from_p12(&p12, password)
        .unwrap_or_else(|e| panic!("Failed to extract key from {}: {}", path, e));
    assert_eq!(key_der[0], 0x30, "{}: not a valid PKCS#8 key", path);
    assert!(key_der.len() > 100, "{}: key too short", path);
}

fn assert_extract_fails(path: &str, password: &str, expected_msg: &str) {
    let p12 = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
    let err = smime::pkcs12_utils::extract_private_key_from_p12(&p12, password).expect_err(&format!("{}: expected failure", path));
    assert!(err.contains(expected_msg), "{}: expected '{}', got: {}", path, expected_msg, err);
}

#[test]
fn pkcs12_key_extraction() {
    assert_extracts_key("tests/nested/certificate.p12", "1234567890");
}

#[test]
fn pkcs12_algorithm_combinations() {
    assert_extracts_key("tests/keys/test_rsa_sha1_aes128.p12", "zone.eu");
    assert_extracts_key("tests/keys/test_rsa_sha384_aes192.p12", "zone.eu");
    assert_extracts_key("tests/keys/test_rsa_sha512_aes256.p12", "zone.eu");
}

#[test]
fn pkcs12_no_mac() {
    assert_extracts_key("tests/keys/test_rsa_nomac.p12", "zone.eu");
}

#[test]
fn pkcs12_wrong_password() {
    assert_extract_fails("tests/nested/certificate.p12", "wrong", "MAC verification failed");
}

#[test]
fn pkcs12_unsupported_mac_algorithm() {
    assert_extract_fails("tests/keys/test_rsa_sha224mac.p12", "zone.eu", "Unsupported MAC digest algorithm");
}

#[test]
fn pkcs12_unsupported_prf() {
    assert_extract_fails("tests/keys/test_rsa_unsupported_prf.p12", "zone.eu", "Unsupported PBKDF2 PRF");
}
