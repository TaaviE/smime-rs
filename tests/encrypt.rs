#![cfg(all(feature = "encrypt", feature = "decrypt"))]

//! Round-trip tests: encrypt with smime::encrypt, then decrypt with smime::decrypt.

use smime::cryptography_x509::pkcs7::{Content, ContentInfo};
use smime::decrypt::{DecryptionKeys, decrypt_auth_enveloped_data, decrypt_enveloped_data};
use smime::encrypt::{ContentCipher, encrypt};
use std::fs;

fn pem_contents(path: &str) -> Vec<u8> {
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

    let der = encrypt(&certs, plaintext, cipher, pkcs1v15).unwrap();

    let keys =
        DecryptionKeys { private_key_der: &pem_contents(key_path), recipient_cert_der: &pem_contents(cert_path), ..Default::default() };
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
fn x25519_cbc() {
    roundtrip("tests/keys/test_x25519.pem", "tests/keys/test_x25519.key", ContentCipher::Aes256Cbc, false);
}

#[test]
fn x25519_gcm() {
    roundtrip("tests/keys/test_x25519.pem", "tests/keys/test_x25519.key", ContentCipher::Aes256Gcm, false);
}

#[test]
fn x25519_kari_uses_rfc8418_hkdf_sha256() {
    use smime::cryptography_x509::oid;
    use smime::cryptography_x509::pkcs7::{OriginatorIdentifierOrKey, RecipientInfo};

    let certs = vec![fs::read_to_string("tests/keys/test_x25519.pem").unwrap()];
    let der = encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).unwrap();
    let ci: ContentInfo = asn1::parse_single(&der).unwrap();
    let enveloped = match ci.content {
        Content::EnvelopedData(e) => e.into_inner(),
        _ => panic!("expected EnvelopedData"),
    };
    let ris: Vec<RecipientInfo> = enveloped.recipient_infos.unwrap_read().clone().collect();
    let kari = match &ris[0] {
        RecipientInfo::KeyAgreeRecipientInfo(kari) => kari,
        _ => panic!("expected KARI"),
    };
    assert_eq!(kari.version, 3);
    assert_eq!(kari.key_encryption_algorithm.oid(), &oid::DH_HKDF_SHA256);
    let originator_key = match &kari.originator {
        OriginatorIdentifierOrKey::OriginatorKey(key) => key,
        _ => panic!("expected originatorKey"),
    };
    assert_eq!(originator_key.algorithm.oid(), &oid::X25519_OID);
    assert_eq!(originator_key.public_key.as_bytes().len(), 32);
}

#[test]
fn multi_recipient_rsa_and_ec() {
    let plaintext = b"multi recipient body";
    let certs = vec![fs::read_to_string("tests/keys/test_rsa.pem").unwrap(), fs::read_to_string("tests/keys/test_p256.pem").unwrap()];
    let der = encrypt(&certs, plaintext, ContentCipher::Aes256Cbc, false).unwrap();

    // Each recipient can independently recover the plaintext.
    let rsa_keys = DecryptionKeys {
        private_key_der: &pem_contents("tests/keys/test_rsa.key"),
        recipient_cert_der: &pem_contents("tests/keys/test_rsa.pem"),
        ..Default::default()
    };
    assert_eq!(decrypt_content_info(&der, &rsa_keys), plaintext);

    let ec_keys = DecryptionKeys {
        private_key_der: &pem_contents("tests/keys/test_p256.key"),
        recipient_cert_der: &pem_contents("tests/keys/test_p256.pem"),
        ..Default::default()
    };
    assert_eq!(decrypt_content_info(&der, &ec_keys), plaintext);
}

#[test]
fn version_reflects_built_recipient_infos() {
    // KTRI-only recipients → version 0 per RFC 5652 §6.1.
    let certs = vec![fs::read_to_string("tests/keys/test_rsa.pem").unwrap()];
    let der = encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).unwrap();
    let ci: ContentInfo = asn1::parse_single(&der).unwrap();
    match ci.content {
        Content::EnvelopedData(e) => assert_eq!(e.into_inner().version, 0),
        _ => panic!("expected EnvelopedData"),
    }

    // A KARI recipient still forces version 2.
    let certs = vec![fs::read_to_string("tests/keys/test_rsa.pem").unwrap(), fs::read_to_string("tests/keys/test_p256.pem").unwrap()];
    let der = encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).unwrap();
    let ci: ContentInfo = asn1::parse_single(&der).unwrap();
    match ci.content {
        Content::EnvelopedData(e) => assert_eq!(e.into_inner().version, 2),
        _ => panic!("expected EnvelopedData"),
    }
}

#[test]
fn unsupported_recipient_is_an_error() {
    // Ed25519 cert is not a supported encryption recipient → error.
    let certs = vec![fs::read_to_string("tests/keys/test_ed25519.pem").unwrap()];
    assert!(encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).is_err());

    // An unsupported recipient among supported ones must not be silently dropped.
    let certs = vec![fs::read_to_string("tests/keys/test_rsa.pem").unwrap(), fs::read_to_string("tests/keys/test_ed25519.pem").unwrap()];
    assert!(encrypt(&certs, b"x", ContentCipher::Aes256Cbc, false).is_err());
}

#[test]
fn no_recipients_is_an_error() {
    assert!(encrypt(&[], b"x", ContentCipher::Aes256Cbc, false).is_err());
}

#[test]
fn validate_cert_key_parity() {
    use smime::encrypt::validate_cert_key;
    // Supported types pass.
    for p in [
        "tests/keys/test_rsa.pem",
        "tests/keys/test_p256.pem",
        "tests/keys/test_p384.pem",
        "tests/keys/test_p521.pem",
        "tests/keys/test_x25519.pem",
    ] {
        validate_cert_key(&fs::read_to_string(p).unwrap()).unwrap_or_else(|e| panic!("{} should validate: {:?}", p, e));
    }
    // Ed25519 is rejected.
    assert!(validate_cert_key(&fs::read_to_string("tests/keys/test_ed25519.pem").unwrap()).is_err());
}
