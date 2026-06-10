#![cfg(feature = "pkcs12")]

use smime::cryptography_x509::certificate::Certificate;
use smime::cryptography_x509::pkcs7::{Content, ContentInfo};
use smime::cryptography_x509::pkcs12::{BagValue, CertBag, CertType, Pfx, SafeBag};
use smime::pkcs12_utils::{P12Error, extract_leaf_certificate_from_p12};

fn assert_extracts_key(path: &str, password: &str) {
    let p12 = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
    let key_der = smime::pkcs12_utils::extract_private_key_from_p12(&p12, password)
        .unwrap_or_else(|e| panic!("Failed to extract key from {}: {}", path, e.into_message()));
    assert_eq!(key_der[0], 0x30, "{}: not a valid PKCS#8 key", path);
    assert!(key_der.len() > 100, "{}: key too short", path);
}

fn assert_extract_fails(path: &str, password: &str, expected_msg: &str) {
    let p12 = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
    let err =
        smime::pkcs12_utils::extract_private_key_from_p12(&p12, password).expect_err(&format!("{}: expected failure", path)).into_message();
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

/// Build a MAC-less, unencrypted cert-only PKCS#12 around the given certificate DERs.
fn cert_only_pfx(cert_ders: &[&[u8]]) -> Vec<u8> {
    let certs: Vec<Certificate> = cert_ders.iter().map(|der| asn1::parse_single(der).unwrap()).collect();
    let bags: Vec<SafeBag> = certs
        .into_iter()
        .map(|cert| SafeBag {
            _bag_id: asn1::DefinedByMarker::marker(),
            bag_value: asn1::Explicit::new(BagValue::CertBag(Box::new(CertBag {
                _cert_id: asn1::DefinedByMarker::marker(),
                cert_value: asn1::Explicit::new(CertType::X509(asn1::OctetStringEncoded::new(cert))),
            }))),
            attributes: None,
        })
        .collect();
    let safe_contents = asn1::write_single(&asn1::SequenceOfWriter::new(bags)).unwrap();
    let auth_safe = asn1::write_single(&asn1::SequenceOfWriter::new([ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::Data(Some(asn1::Explicit::new(&safe_contents))),
    }]))
    .unwrap();
    asn1::write_single(&Pfx {
        version: 3,
        auth_safe: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(&auth_safe))),
        },
        mac_data: None,
    })
    .unwrap()
}

#[test]
fn pkcs12_leaf_certificate_extraction() {
    // certificate.p12 holds leaf + intermediate CA + root CA; only the leaf may be returned
    let p12 = std::fs::read("tests/nested/certificate.p12").unwrap();
    let der = extract_leaf_certificate_from_p12(&p12, "1234567890").unwrap();
    asn1::parse_single::<Certificate>(&der).expect("extracted leaf is not a valid certificate");
    let email = b"dpa.test@sandbox.comarch.com";
    assert!(der.windows(email.len()).any(|w| w == email), "extracted certificate is not the expected leaf");
}

#[test]
fn pkcs12_leaf_certificate_wrong_password() {
    let p12 = std::fs::read("tests/nested/certificate.p12").unwrap();
    assert!(matches!(extract_leaf_certificate_from_p12(&p12, "wrong"), Err(P12Error::WrongPassword(_))));
    // empty password (the no-password wasm path) must also be classified as a credential failure
    assert!(matches!(extract_leaf_certificate_from_p12(&p12, ""), Err(P12Error::WrongPassword(_))));
}

#[test]
fn pkcs12_no_leaf_certificate() {
    // the only cert in this bundle is self-signed with basicConstraints CA:TRUE
    let p12 = std::fs::read("tests/keys/test_rsa_sha1_aes128.p12").unwrap();
    assert!(matches!(extract_leaf_certificate_from_p12(&p12, "zone.eu"), Err(P12Error::NoLeafCertificate)));
}

#[test]
fn pkcs12_cert_only_openssl_bundle() {
    // openssl pkcs12 -export -nokeys over the certificate.p12 chain (OpenSSL 3.5: SHA-256 MAC, PBES2 AES-256-CBC)
    let p12 = std::fs::read("tests/keys/test_certonly.p12").unwrap();
    let leaf_der = extract_leaf_certificate_from_p12(&std::fs::read("tests/nested/certificate.p12").unwrap(), "1234567890").unwrap();
    assert_eq!(extract_leaf_certificate_from_p12(&p12, "zone.eu").unwrap(), leaf_der);
}

#[test]
fn pkcs12_null_password_mac_flavor() {
    // A passwordless file whose MAC key was derived from a zero-length password
    // (the NULL flavor) instead of an empty BMPString with its two-byte terminator.
    // Like OpenSSL, both flavors must open with an empty password.
    use pbkdf2::hmac::{Hmac, Mac, digest::KeyInit};
    use smime::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
    use smime::cryptography_x509::pkcs7::DigestInfo;
    use smime::cryptography_x509::pkcs12::MacData;

    let leaf_der = extract_leaf_certificate_from_p12(&std::fs::read("tests/nested/certificate.p12").unwrap(), "1234567890").unwrap();
    let unmacced = cert_only_pfx(&[&leaf_der]);
    let pfx = asn1::parse_single::<Pfx>(&unmacced).unwrap();
    let Content::Data(Some(auth_safe_bytes)) = &pfx.auth_safe.content else { unreachable!() };

    let salt = [7u8; 8];
    let mac_key = pkcs12::kdf::derive_key::<sha2::Sha256>(&[], &salt, pkcs12::kdf::Pkcs12KeyType::Mac, 2048, 32);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&mac_key).unwrap();
    mac.update(auth_safe_bytes.as_inner());
    let digest = mac.finalize().into_bytes();

    let p12 = asn1::write_single(&Pfx {
        version: 3,
        auth_safe: pfx.auth_safe,
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha256(Some(())) },
                digest: &digest,
            },
            salt: &salt,
            iterations: 2048,
        }),
    })
    .unwrap();

    assert_eq!(extract_leaf_certificate_from_p12(&p12, "").unwrap(), leaf_der);
    // a non-empty password must still fail against either flavor
    assert!(matches!(extract_leaf_certificate_from_p12(&p12, "wrong"), Err(P12Error::WrongPassword(_))));
}

#[test]
fn pkcs12_unsupported_version() {
    let leaf_der = extract_leaf_certificate_from_p12(&std::fs::read("tests/nested/certificate.p12").unwrap(), "1234567890").unwrap();
    let v3 = cert_only_pfx(&[&leaf_der]);
    let pfx = asn1::parse_single::<Pfx>(&v3).unwrap();
    let p12 = asn1::write_single(&Pfx { version: 2, auth_safe: pfx.auth_safe, mac_data: None }).unwrap();
    let err = extract_leaf_certificate_from_p12(&p12, "").expect_err("PFX version 2 accepted").into_message();
    assert!(err.contains("Unsupported PFX version: 2"), "unexpected error: {}", err);
}

/// Build a MAC-less PKCS#12 whose AuthenticatedSafe holds a PBES2 EncryptedData
/// (AES-128-CBC) with the given PBKDF2 parameters. The ciphertext is filler:
/// parameter validation must fail before decryption is attempted.
fn pbes2_pfx(iteration_count: u64, key_length: Option<u64>) -> Vec<u8> {
    use smime::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters, PBES2Params, PBKDF2Params};
    use smime::cryptography_x509::pkcs7::{EncryptedContentInfo, EncryptedData, PKCS7_DATA_OID};

    let salt = [7u8; 8];
    let ciphertext = [0u8; 16];
    let prf = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::HmacWithSha256(Some(())) };
    let kdf = AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Pbkdf2(PBKDF2Params { salt: &salt, iteration_count, key_length, prf: Box::new(prf) }),
    };
    let scheme = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Aes128Cbc([0u8; 16]) };
    let encrypted = EncryptedData {
        version: 0,
        encrypted_content_info: EncryptedContentInfo {
            content_type: PKCS7_DATA_OID.clone(),
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Pbes2(PBES2Params { key_derivation_func: Box::new(kdf), encryption_scheme: Box::new(scheme) }),
            },
            encrypted_content: Some(&ciphertext),
        },
        unprotected_attrs: None,
    };
    let auth_safe = asn1::write_single(&asn1::SequenceOfWriter::new([ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::EncryptedData(asn1::Explicit::new(encrypted)),
    }]))
    .unwrap();
    asn1::write_single(&Pfx {
        version: 3,
        auth_safe: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(&auth_safe))),
        },
        mac_data: None,
    })
    .unwrap()
}

#[test]
fn pkcs12_pbes2_zero_iteration_count() {
    let err = smime::pkcs12_utils::extract_private_key_from_p12(&pbes2_pfx(0, None), "zone.eu")
        .expect_err("PBKDF2 iteration count 0 accepted")
        .into_message();
    assert!(err.contains("iteration count 0"), "unexpected error: {}", err);
}

#[test]
fn pkcs12_pbes2_key_length_mismatch() {
    let err = smime::pkcs12_utils::extract_private_key_from_p12(&pbes2_pfx(2048, Some(32)), "zone.eu")
        .expect_err("PBKDF2 keyLength mismatch accepted")
        .into_message();
    assert!(err.contains("keyLength 32 does not match cipher key length 16"), "unexpected error: {}", err);
}

#[test]
fn pkcs12_cert_only_unprotected_bundle() {
    let leaf_der = extract_leaf_certificate_from_p12(&std::fs::read("tests/nested/certificate.p12").unwrap(), "1234567890").unwrap();
    let ca_der = pem::parse(std::fs::read("tests/keys/test_rsa.pem").unwrap()).unwrap().into_contents();

    // CA first, leaf second: the CA must be skipped even though it comes first
    let p12 = cert_only_pfx(&[&ca_der, &leaf_der]);
    assert_eq!(extract_leaf_certificate_from_p12(&p12, "").unwrap(), leaf_der);
}
