#![cfg(feature = "decrypt")]

//! Round-trip tests: encrypt with smime::encrypt, then decrypt with smime::decrypt.

use smime::cryptography_x509::pkcs7::{Content, ContentInfo};
use smime::decrypt::{decrypt_auth_enveloped_data, decrypt_enveloped_data, DecryptionKeys};
use smime::encrypt::{encrypt, ContentCipher};
use std::fs;

fn key_der(path: &str) -> Vec<u8> {
    pem::parse(fs::read_to_string(path).unwrap()).unwrap().into_contents()
}

fn cert_der(path: &str) -> Vec<u8> {
    pem::parse(fs::read_to_string(path).unwrap()).unwrap().into_contents()
}

fn decrypt_content_info(der: &[u8], keys: &DecryptionKeys) -> Vec<u8> {
    let ci: ContentInfo = asn1::parse_single(der).unwrap();
    match ci.content {
        Content::EnvelopedData(e) => decrypt_enveloped_data(&e.into_inner(), keys).unwrap().0.unwrap(),
        Content::AuthEnvelopedData(e) => decrypt_auth_enveloped_data(&e.into_inner(), keys).unwrap().0.unwrap(),
        _ => panic!("expected EnvelopedData or AuthEnvelopedData"),
    }
}

fn roundtrip(cert_path: &str, key_path: &str, cipher: ContentCipher, pkcs1v15: bool) {
    let plaintext = b"Content-Type: text/plain\r\n\r\nHello, S/MIME encryption!\r\n";
    let certs = vec![fs::read_to_string(cert_path).unwrap()];

    let der = encrypt(&certs, plaintext, cipher, pkcs1v15).unwrap().expect("encrypt produced no recipients");

    let keys = DecryptionKeys { private_key_der: &key_der(key_path), recipient_cert_der: &cert_der(cert_path), ..Default::default() };
    let recovered = decrypt_content_info(&der, &keys);
    assert_eq!(recovered, plaintext);
}

#[test]
fn rsa_oaep_cbc() {
    roundtrip("tests/keys/test_rsa.pem", "tests/keys/test_rsa.key", ContentCipher::Aes256Cbc, false);
}

#[test]
fn rsa_oaep_gcm() {
    roundtrip("tests/keys/test_rsa.pem", "tests/keys/test_rsa.key", ContentCipher::Aes256Gcm, false);
}

#[test]
fn rsa_pkcs1v15_cbc() {
    roundtrip("tests/keys/test_rsa.pem", "tests/keys/test_rsa.key", ContentCipher::Aes256Cbc, true);
}

#[test]
fn p256_cbc() {
    roundtrip("tests/keys/test_p256.pem", "tests/keys/test_p256.key", ContentCipher::Aes256Cbc, false);
}

#[test]
fn p384_gcm() {
    roundtrip("tests/keys/test_p384.pem", "tests/keys/test_p384.key", ContentCipher::Aes256Gcm, false);
}

#[test]
fn p521_cbc() {
    roundtrip("tests/keys/test_p521.pem", "tests/keys/test_p521.key", ContentCipher::Aes256Cbc, false);
}

#[test]
fn multi_recipient_rsa_and_ec() {
    let plaintext = b"multi recipient body";
    let certs = vec![fs::read_to_string("tests/keys/test_rsa.pem").unwrap(), fs::read_to_string("tests/keys/test_p256.pem").unwrap()];
    let der = encrypt(&certs, plaintext, ContentCipher::Aes256Cbc, false).unwrap().unwrap();

    // Each recipient can independently recover the plaintext.
    let rsa_keys = DecryptionKeys {
        private_key_der: &key_der("tests/keys/test_rsa.key"),
        recipient_cert_der: &cert_der("tests/keys/test_rsa.pem"),
        ..Default::default()
    };
    assert_eq!(decrypt_content_info(&der, &rsa_keys), plaintext);

    let ec_keys = DecryptionKeys {
        private_key_der: &key_der("tests/keys/test_p256.key"),
        recipient_cert_der: &cert_der("tests/keys/test_p256.pem"),
        ..Default::default()
    };
    assert_eq!(decrypt_content_info(&der, &ec_keys), plaintext);
}

#[test]
fn no_valid_recipients_returns_none() {
    // Ed25519 cert is not a supported encryption recipient → None.
    let certs = vec![fs::read_to_string("tests/keys/test_ed25519.pem").unwrap()];
    let out = encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).unwrap();
    assert!(out.is_none());
}

#[test]
fn validate_cert_key_parity() {
    use smime::encrypt::validate_cert_key;
    // Supported types pass.
    for p in ["tests/keys/test_rsa.pem", "tests/keys/test_p256.pem", "tests/keys/test_p384.pem", "tests/keys/test_p521.pem"] {
        validate_cert_key(&fs::read_to_string(p).unwrap()).unwrap_or_else(|e| panic!("{} should validate: {:?}", p, e));
    }
    // Ed25519 is rejected.
    assert!(validate_cert_key(&fs::read_to_string("tests/keys/test_ed25519.pem").unwrap()).is_err());
}
