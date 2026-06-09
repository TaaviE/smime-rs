use aes_kw::KeyInit;
use base64::prelude::*;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use clap::{Parser, Subcommand};
use smime::cryptography_x509::certificate::{TbsCertificate, Validity};
use smime::cryptography_x509::common::*;
use smime::cryptography_x509::csr;
use smime::cryptography_x509::name;
use smime::cryptography_x509::oid;
use smime::cryptography_x509::pkcs7::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Generate test S/MIME fixture .eml files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate signature fixtures
    Sign {
        #[command(subcommand)]
        command: SignCommands,
    },
    /// Generate encryption fixtures
    Encrypt {
        #[command(subcommand)]
        command: EncryptCommands,
    },
    /// Generate stapled-OCSP validity-extension fixtures
    Ocsp,
    /// Run all generators
    All,
}

#[derive(Subcommand)]
enum SignCommands {
    /// Ed25519 signature with SHA-512 digest
    Ed25519 {
        #[arg(long, default_value = "tests/general/ed25519.eml")]
        output: PathBuf,
    },
    /// ML-DSA-44 signature with SHAKE-128 digest
    MlDsa44Shake128 {
        #[arg(long, default_value = "tests/pq/ml-dsa-44-shake128.eml")]
        output: PathBuf,
    },
    /// ML-DSA-44 signature with SHAKE-256 digest
    MlDsa44Shake {
        #[arg(long, default_value = "tests/pq/ml-dsa-44-shake.eml")]
        output: PathBuf,
    },
    /// ML-DSA-65 signature with SHAKE-256 digest
    MlDsa65Shake {
        #[arg(long, default_value = "tests/pq/ml-dsa-65.eml")]
        output: PathBuf,
    },
    /// ML-DSA-87 signature with SHAKE-256 digest
    MlDsa87Shake {
        #[arg(long, default_value = "tests/pq/ml-dsa-87.eml")]
        output: PathBuf,
    },
    /// Signed message with no message-digest attribute
    NoMessageDigest {
        #[arg(long, default_value = "tests/general/no-message-digest-attr.eml")]
        output: PathBuf,
    },
    /// Signed message with no authenticated attributes
    NoAuthAttrs {
        #[arg(long, default_value = "tests/general/no-auth-attrs.eml")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum EncryptCommands {
    /// OpenSSL-generated fixtures (RSA, OAEP, ECDH, GCM, CCM, PWRI)
    Openssl,
    /// Rust-native fixtures for algorithms OpenSSL can't generate
    Additional,
    /// Multi-recipient-type fixtures (KTRI + KARI + KEKRI + PWRI)
    MultiRecipient,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).unwrap();
    buf
}

fn utf8_attr_value(s: &str) -> AttributeValue<'_> {
    AttributeValue::AnyString(RawTlv::new(asn1::Tag::primitive(0x0c), s.as_bytes()))
}

fn build_name_der(cn: &str) -> Vec<u8> {
    let org_oid = asn1::oid!(2, 5, 4, 10);
    let org_attr = AttributeTypeValue { type_id: org_oid, value: utf8_attr_value("Zone Media OÜ") };
    let cn_attr = AttributeTypeValue { type_id: oid::COMMON_NAME_OID, value: utf8_attr_value(cn) };

    let name_val: name::Name<'_> = Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(vec![
        asn1::SetOfWriter::new(vec![org_attr]),
        asn1::SetOfWriter::new(vec![cn_attr]),
    ]));

    asn1::write_single(&name_val).unwrap()
}

fn build_validity() -> Validity {
    Validity {
        not_before: Time::UtcTime(asn1::UtcTime::new(asn1::DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()).unwrap()),
        not_after: Time::UtcTime(asn1::UtcTime::new(asn1::DateTime::new(2040, 1, 1, 0, 0, 0).unwrap()).unwrap()),
    }
}

fn build_certificate_der(
    sig_alg: &AlgorithmIdentifier<'_>,
    spki_alg: &AlgorithmIdentifier<'_>,
    pub_key_bytes: &[u8],
    cn: &str,
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut serial_bytes = random_bytes::<16>().to_vec();
    serial_bytes[0] &= 0x7F;

    let name_der = build_name_der(cn);

    let spki = SubjectPublicKeyInfo { algorithm: spki_alg.clone(), subject_public_key: asn1::BitString::new(pub_key_bytes, 0).unwrap() };
    let spki_der = asn1::write_single(&spki).unwrap();

    let validity = build_validity();

    let spki_with_tlv: WithTlv<'_, SubjectPublicKeyInfo<'_>> = asn1::parse_single(&spki_der).unwrap();
    let issuer: name::NameReadable<'_> = asn1::parse_single(&name_der).unwrap();
    let subject: name::NameReadable<'_> = asn1::parse_single(&name_der).unwrap();

    let tbs = TbsCertificate {
        version: 2,
        serial: asn1::BigInt::new(&serial_bytes).unwrap(),
        signature_alg: sig_alg.clone(),
        issuer: Asn1ReadableOrWritable::new_read(issuer),
        validity,
        subject: Asn1ReadableOrWritable::new_read(subject),
        spki: spki_with_tlv,
        issuer_unique_id: None,
        subject_unique_id: None,
        raw_extensions: None,
    };

    let tbs_der = asn1::write_single(&tbs).unwrap();
    let signature_bytes = sign(&tbs_der);

    let sig_bs = asn1::OwnedBitString::new(signature_bytes, 0).unwrap();

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let tbs_tlv: asn1::Tlv<'_> = asn1::parse_single(&tbs_der).unwrap();
    let cert_der = asn1::write_single(&asn1::SequenceWriter::new(&|w| -> asn1::WriteResult {
        w.write_element(&tbs_tlv)?;
        w.write_element(sig_alg)?;
        w.write_element(&sig_bs)?;
        Ok(())
    }))
    .unwrap();

    (cert_der, serial_bytes, name_der)
}

fn build_cms_der(
    cert_der: &[u8],
    serial_bytes: &[u8],
    name_der: &[u8],
    content: &[u8],
    digest_alg: &AlgorithmIdentifier<'_>,
    sig_alg: &AlgorithmIdentifier<'_>,
    content_hash: &[u8],
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let data_oid_der = asn1::write_single(&PKCS7_DATA_OID).unwrap();
    let data_oid_tlv: asn1::Tlv<'_> = asn1::parse_single(&data_oid_der).unwrap();

    let content_type_attr = csr::Attribute {
        type_id: oid::CONTENT_TYPE_OID,
        values: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([RawTlv::new(data_oid_tlv.tag(), data_oid_tlv.data())])),
    };

    let digest_octet_tag = <&[u8] as asn1::SimpleAsn1Readable>::TAG;
    let message_digest_attr = csr::Attribute {
        type_id: oid::MESSAGE_DIGEST_OID,
        values: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([RawTlv::new(digest_octet_tag, content_hash)])),
    };

    let attrs = vec![content_type_attr, message_digest_attr];
    let attrs_set = asn1::SetOfWriter::new(attrs);
    let attrs_set_der = asn1::write_single(&attrs_set).unwrap();

    let attrs_signature = sign(&attrs_set_der);

    let parsed_attrs: asn1::SetOf<'_, csr::Attribute<'_>> = asn1::parse_single(&attrs_set_der).unwrap();

    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(cert_der).unwrap();

    let issuer_name: name::NameReadable<'_> = asn1::parse_single(name_der).unwrap();

    let signer_info = SignerInfo {
        version: 1,
        issuer_and_serial_number: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Asn1ReadableOrWritable::new_read(issuer_name),
            serial_number: asn1::BigInt::new(serial_bytes).unwrap(),
        }),
        digest_algorithm: digest_alg.clone(),
        authenticated_attributes: Some(Asn1ReadableOrWritable::new_read(parsed_attrs)),
        digest_encryption_algorithm: sig_alg.clone(),
        encrypted_digest: &attrs_signature,
        unauthenticated_attributes: None,
    };

    let digest_algs = [digest_alg.clone()];
    let signer_infos = [signer_info];

    let signed_data = SignedData {
        version: 1,
        digest_algorithms: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&digest_algs)),
        content_info: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(content))),
        },
        certificates: Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(vec![CertificateChoices::Certificate(cert)]))),
        crls: None,
        signer_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&signer_infos)),
    };

    let content_info = ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };

    asn1::write_single(&content_info).unwrap()
}

fn write_fixture_eml(path: impl AsRef<std::path::Path>, cms_der: &[u8], subject: &str, smime_type: &str) {
    let b64 = BASE64_STANDARD.encode(cms_der);
    let body: String = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\r\n");

    let (from, to) = if smime_type.contains("signed") {
        ("=?UTF-8?B?QW51IEFsbGtpcmphc3RhamE=?= <anu@naide.ee>", "=?UTF-8?B?VGlpdSBUaWhhbmU=?= <tiiu@naide.ee>")
    } else {
        ("=?UTF-8?B?S2FsbGUgS3LDvHB0aWph?= <kalle@naide.ee>", "=?UTF-8?B?VGlpdSBUaWhhbmU=?= <tiiu@naide.ee>")
    };

    let headers = [
        format!("From: {from}"),
        format!("To: {to}"),
        format!("Subject: {subject}"),
        format!("Date: {}", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")),
        format!("MIME-Version: 1.0"),
        format!("Content-Type: application/pkcs7-mime;\r\n smime-type={smime_type}; name=\"smime.p7m\""),
        format!("Content-Disposition: attachment; filename=\"smime.p7m\""),
        format!("Content-Transfer-Encoding: base64"),
    ];

    let mut eml = headers.join("\r\n");
    eml.push_str("\r\n\r\n");
    eml.push_str(&body);
    eml.push_str("\r\n");

    let path = path.as_ref();
    fs::write(path, &eml).unwrap();
    eprintln!("Wrote {}", path.display());
}

fn verify_signed_cms(cms_der: &[u8]) {
    let ci: ContentInfo = asn1::parse_single(cms_der).unwrap();
    match ci.content {
        Content::SignedData(sd) => {
            let sd = *sd.into_inner();
            let signers: Vec<_> = sd.signer_infos.unwrap_read().clone().collect();
            assert!(!signers.is_empty(), "no signer infos in generated CMS");
        }
        _ => panic!("expected SignedData"),
    }
}

use smime::encrypt::encrypt_aes_cbc;

fn verify_enveloped_roundtrip(der: &[u8], keys: &smime::decrypt::DecryptionKeys, expected: &[u8]) {
    let parsed: ContentInfo = asn1::parse_single(der).unwrap();
    let env = match parsed.content {
        Content::EnvelopedData(e) => e.into_inner(),
        _ => panic!("expected EnvelopedData"),
    };
    let pt = smime::decrypt::decrypt_enveloped_data(&env, keys).expect("decrypt");
    assert_eq!(pt.0.as_deref(), Some(expected));
}

#[cfg(feature = "decrypt-ccm")]
fn verify_auth_enveloped_roundtrip(der: &[u8], keys: &smime::decrypt::DecryptionKeys, expected: &[u8]) {
    let parsed: ContentInfo = asn1::parse_single(der).unwrap();
    let aed = match parsed.content {
        Content::AuthEnvelopedData(e) => e.into_inner(),
        _ => panic!("expected AuthEnvelopedData"),
    };
    let pt = smime::decrypt::decrypt_auth_enveloped_data(&aed, keys).expect("decrypt");
    assert_eq!(pt.0.as_deref(), Some(expected));
}

fn generate_no_message_digest(output: &PathBuf) {
    use rsa::pkcs8::DecodePrivateKey;
    use signature::SignatureEncoding;

    let cert_der = load_cert_der_for_fixtures("tests/keys/test_rsa.pem");
    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let issuer_der = asn1::write_single(&cert.tbs_cert.issuer).unwrap();
    let serial_bytes = cert.tbs_cert.serial.as_bytes().to_vec();

    let key_pem = fs::read_to_string("tests/keys/test_rsa.key").expect("read RSA key");
    let rsa_sk = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem).expect("parse RSA key");

    let content = b"Content-Type: text/plain\r\n\r\nNo message-digest attribute\r\n";

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::RsaWithSha256(Some(())) };
    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha256(Some(())) };

    // Build signed attributes with only content-type (no message-digest)
    let data_oid_der = asn1::write_single(&PKCS7_DATA_OID).unwrap();
    let data_oid_tlv: asn1::Tlv<'_> = asn1::parse_single(&data_oid_der).unwrap();
    let content_type_attr = csr::Attribute {
        type_id: oid::CONTENT_TYPE_OID,
        values: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([RawTlv::new(data_oid_tlv.tag(), data_oid_tlv.data())])),
    };

    let attrs = vec![content_type_attr];
    let attrs_set = asn1::SetOfWriter::new(attrs);
    let attrs_set_der = asn1::write_single(&attrs_set).unwrap();

    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_sk);
    let attrs_signature = {
        use signature::Signer;
        signer.sign(&attrs_set_der).to_vec()
    };

    let parsed_attrs: asn1::SetOf<'_, csr::Attribute<'_>> = asn1::parse_single(&attrs_set_der).unwrap();
    let parsed_cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let issuer_name: name::NameReadable<'_> = asn1::parse_single(&issuer_der).unwrap();

    let signer_info = SignerInfo {
        version: 1,
        issuer_and_serial_number: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Asn1ReadableOrWritable::new_read(issuer_name),
            serial_number: asn1::BigInt::new(&serial_bytes).unwrap(),
        }),
        digest_algorithm: digest_alg.clone(),
        authenticated_attributes: Some(Asn1ReadableOrWritable::new_read(parsed_attrs)),
        digest_encryption_algorithm: sig_alg.clone(),
        encrypted_digest: &attrs_signature,
        unauthenticated_attributes: None,
    };

    let digest_algs = [digest_alg];
    let signer_infos = [signer_info];

    let signed_data = SignedData {
        version: 1,
        digest_algorithms: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&digest_algs)),
        content_info: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(content.as_slice()))),
        },
        certificates: Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(vec![CertificateChoices::Certificate(parsed_cert)]))),
        crls: None,
        signer_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&signer_infos)),
    };

    let content_info = ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };

    let cms_der = asn1::write_single(&content_info).unwrap();
    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test No Message Digest", "signed-data");
}

fn generate_no_auth_attrs(output: &PathBuf) {
    use rsa::pkcs8::DecodePrivateKey;
    use signature::SignatureEncoding;

    let cert_der = load_cert_der_for_fixtures("tests/keys/test_rsa.pem");
    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let issuer_der = asn1::write_single(&cert.tbs_cert.issuer).unwrap();
    let serial_bytes = cert.tbs_cert.serial.as_bytes().to_vec();

    let key_pem = fs::read_to_string("tests/keys/test_rsa.key").expect("read RSA key");
    let rsa_sk = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem).expect("parse RSA key");

    let content = b"Content-Type: text/plain\r\n\r\nNo authenticated attributes\r\n";

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::RsaWithSha256(Some(())) };
    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha256(Some(())) };

    // Sign the content directly (RFC 5652 §5.4: no signed attributes means sig covers content)
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_sk);
    let content_signature = {
        use signature::Signer;
        signer.sign(content.as_slice()).to_vec()
    };

    let parsed_cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let issuer_name: name::NameReadable<'_> = asn1::parse_single(&issuer_der).unwrap();

    let signer_info = SignerInfo {
        version: 1,
        issuer_and_serial_number: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Asn1ReadableOrWritable::new_read(issuer_name),
            serial_number: asn1::BigInt::new(&serial_bytes).unwrap(),
        }),
        digest_algorithm: digest_alg.clone(),
        authenticated_attributes: None,
        digest_encryption_algorithm: sig_alg.clone(),
        encrypted_digest: &content_signature,
        unauthenticated_attributes: None,
    };

    let digest_algs = [digest_alg];
    let signer_infos = [signer_info];

    let signed_data = SignedData {
        version: 1,
        digest_algorithms: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&digest_algs)),
        content_info: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(content.as_slice()))),
        },
        certificates: Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(vec![CertificateChoices::Certificate(parsed_cert)]))),
        crls: None,
        signer_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&signer_infos)),
    };

    let content_info = ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };

    let cms_der = asn1::write_single(&content_info).unwrap();
    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test No Auth Attrs", "signed-data");
}

fn generate_ed25519(output: &PathBuf) {
    use ed25519_dalek::Signer;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let key_pem = fs::read_to_string("tests/keys/test_ed25519.key").expect("Failed to read tests/keys/test_ed25519.key");
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(&key_pem).expect("Failed to parse Ed25519 private key");

    let cert_der = load_cert_der_for_fixtures("tests/keys/test_ed25519.pem");

    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).expect("Failed to parse certificate");
    let issuer_der = asn1::write_single(&cert.tbs_cert.issuer).unwrap();
    let serial_bytes = cert.tbs_cert.serial.as_bytes().to_vec();

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Ed25519 };

    let sign_fn = |data: &[u8]| -> Vec<u8> { signing_key.sign(data).to_bytes().to_vec() };

    let content = b"Hello from Ed25519!";
    let content_hash = {
        use sha2::Digest;
        sha2::Sha512::digest(content).to_vec()
    };

    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha512(Some(())) };

    let cms_der = build_cms_der(&cert_der, &serial_bytes, &issuer_der, content, &digest_alg, &sig_alg, &content_hash, &sign_fn);
    verify_signed_cms(&cms_der);

    write_fixture_eml(output, &cms_der, "Test Ed25519", "signed-data");
}

fn generate_ml_dsa_44_shake128(output: &PathBuf) {
    use libcrux_ml_dsa::ml_dsa_44;

    let key_randomness = random_bytes::<32>();
    let keypair = ml_dsa_44::generate_key_pair(key_randomness);

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::MlDsa44 };
    let spki_alg = sig_alg.clone();

    let sign_fn = |data: &[u8]| -> Vec<u8> {
        let sign_randomness = random_bytes::<32>();
        let sig = ml_dsa_44::sign(&keypair.signing_key, data, &[], sign_randomness).unwrap();
        sig.as_ref().to_vec()
    };

    let (cert_der, serial_bytes, name_der) =
        build_certificate_der(&sig_alg, &spki_alg, keypair.verification_key.as_ref(), "Anu Allkirjastaja", &sign_fn);

    let content = b"Hello from ML-DSA-44-SHAKE128!";
    let content_hash = libcrux_sha3::shake128::<32>(content).to_vec();

    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Shake128 };

    let cms_der = build_cms_der(&cert_der, &serial_bytes, &name_der, content, &digest_alg, &sig_alg, &content_hash, &sign_fn);

    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test ML-DSA-44 SHAKE-128", "signed-data");
}

fn generate_ml_dsa_44_shake(output: &PathBuf) {
    use libcrux_ml_dsa::ml_dsa_44;

    let key_randomness = random_bytes::<32>();
    let keypair = ml_dsa_44::generate_key_pair(key_randomness);

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::MlDsa44 };
    let spki_alg = sig_alg.clone();

    let sign_fn = |data: &[u8]| -> Vec<u8> {
        let sign_randomness = random_bytes::<32>();
        let sig = ml_dsa_44::sign(&keypair.signing_key, data, &[], sign_randomness).unwrap();
        sig.as_ref().to_vec()
    };

    let (cert_der, serial_bytes, name_der) =
        build_certificate_der(&sig_alg, &spki_alg, keypair.verification_key.as_ref(), "Anu Allkirjastaja", &sign_fn);

    let content = b"Hello from ML-DSA-44-SHAKE!";
    let content_hash = libcrux_sha3::shake256::<64>(content).to_vec();

    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Shake256 };

    let cms_der = build_cms_der(&cert_der, &serial_bytes, &name_der, content, &digest_alg, &sig_alg, &content_hash, &sign_fn);

    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test ML-DSA-44 SHAKE-256", "signed-data");
}

fn generate_ml_dsa_65_shake(output: &PathBuf) {
    use libcrux_ml_dsa::ml_dsa_65;

    let key_randomness = random_bytes::<32>();
    let keypair = ml_dsa_65::generate_key_pair(key_randomness);

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::MlDsa65 };
    let spki_alg = sig_alg.clone();

    let sign_fn = |data: &[u8]| -> Vec<u8> {
        let sign_randomness = random_bytes::<32>();
        let sig = ml_dsa_65::sign(&keypair.signing_key, data, &[], sign_randomness).unwrap();
        sig.as_ref().to_vec()
    };

    let (cert_der, serial_bytes, name_der) =
        build_certificate_der(&sig_alg, &spki_alg, keypair.verification_key.as_ref(), "Anu Allkirjastaja", &sign_fn);

    let content = b"Hello from ML-DSA-65!";
    let content_hash = libcrux_sha3::shake256::<64>(content).to_vec();
    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Shake256 };
    let cms_der = build_cms_der(&cert_der, &serial_bytes, &name_der, content, &digest_alg, &sig_alg, &content_hash, &sign_fn);

    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test ML-DSA-65", "signed-data");
}

fn generate_ml_dsa_87_shake(output: &PathBuf) {
    use libcrux_ml_dsa::ml_dsa_87;

    let key_randomness = random_bytes::<32>();
    let keypair = ml_dsa_87::generate_key_pair(key_randomness);

    let sig_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::MlDsa87 };
    let spki_alg = sig_alg.clone();

    let sign_fn = |data: &[u8]| -> Vec<u8> {
        let sign_randomness = random_bytes::<32>();
        let sig = ml_dsa_87::sign(&keypair.signing_key, data, &[], sign_randomness).unwrap();
        sig.as_ref().to_vec()
    };

    let (cert_der, serial_bytes, name_der) =
        build_certificate_der(&sig_alg, &spki_alg, keypair.verification_key.as_ref(), "Anu Allkirjastaja", &sign_fn);

    let content = b"Hello from ML-DSA-87!";
    let content_hash = libcrux_sha3::shake256::<64>(content).to_vec();
    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Shake256 };
    let cms_der = build_cms_der(&cert_der, &serial_bytes, &name_der, content, &digest_alg, &sig_alg, &content_hash, &sign_fn);

    verify_signed_cms(&cms_der);
    write_fixture_eml(output, &cms_der, "Test ML-DSA-87", "signed-data");
}

fn gen_x25519_fixtures() {
    use hkdf::Hkdf;
    let recipient_sk = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(hex::decode("B8CA0426D44BADBF6D8749F4459804459D7177769689CBC1D6456D08DE843667").unwrap()).unwrap(),
    );
    let recipient_pk = x25519_dalek::PublicKey::from(&recipient_sk);

    let eph_sk = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap()).unwrap(),
    );
    let eph_pk = x25519_dalek::PublicKey::from(&eph_sk);
    let shared_secret = eph_sk.diffie_hellman(&recipient_pk);

    struct Variant {
        name: &'static str,
        kea_oid: asn1::ObjectIdentifier,
        kek: Vec<u8>,
    }

    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
        },
        entity_u_info: None,
        supp_pub_info: &0x00000080u32.to_be_bytes(),
    };
    let shared_info_der = asn1::write_single(&shared_info).unwrap();

    let z = shared_secret.as_bytes();

    let mut x963_sha256_kek = vec![0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(z, &shared_info_der, &mut x963_sha256_kek).unwrap();
    let mut x963_sha384_kek = vec![0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha384>(z, &shared_info_der, &mut x963_sha384_kek).unwrap();
    let mut x963_sha512_kek = vec![0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha512>(z, &shared_info_der, &mut x963_sha512_kek).unwrap();

    let mut hkdf256_kek = vec![0u8; 16];
    Hkdf::<sha2::Sha256>::new(Some(&[]), z).expand(&shared_info_der, &mut hkdf256_kek).unwrap();
    let mut hkdf384_kek = vec![0u8; 16];
    Hkdf::<sha2::Sha384>::new(Some(&[]), z).expand(&shared_info_der, &mut hkdf384_kek).unwrap();
    let mut hkdf512_kek = vec![0u8; 16];
    Hkdf::<sha2::Sha512>::new(Some(&[]), z).expand(&shared_info_der, &mut hkdf512_kek).unwrap();

    let variants = [
        Variant { name: "x25519", kea_oid: oid::DH_STD_SHA256.clone(), kek: x963_sha256_kek },
        Variant { name: "x25519_x963_sha384", kea_oid: oid::DH_STD_SHA384.clone(), kek: x963_sha384_kek },
        Variant { name: "x25519_x963_sha512", kea_oid: oid::DH_STD_SHA512.clone(), kek: x963_sha512_kek },
        Variant { name: "x25519_hkdf256", kea_oid: oid::DH_HKDF_SHA256.clone(), kek: hkdf256_kek },
        Variant { name: "x25519_hkdf384", kea_oid: oid::DH_HKDF_SHA384.clone(), kek: hkdf384_kek },
        Variant { name: "x25519_hkdf512", kea_oid: oid::DH_HKDF_SHA512.clone(), kek: hkdf512_kek },
    ];

    let cek: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
    let iv: [u8; 16] = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap().try_into().unwrap();

    let plaintext = b"deterministic X25519 test";
    let ciphertext = encrypt_aes_cbc(&cek, &iv, plaintext);

    let wrap_alg_der = asn1::write_single(&AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
    })
    .unwrap();

    let cert_der = pem::parse(fs::read("tests/keys/test_x25519.pem").expect("read cert")).expect("parse cert PEM").into_contents();

    for v in &variants {
        let originator_key = OriginatorPublicKey {
            algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::X25519 },
            public_key: asn1::BitString::new(eph_pk.as_bytes(), 0).unwrap(),
        };
        let wrap_alg_tlv: asn1::Tlv = asn1::parse_single(&wrap_alg_der).unwrap();
        let mut wrapped_cek = vec![0u8; 24];
        aes_kw::KwAes128::new_from_slice(&v.kek).unwrap().wrap_key(&cek, &mut wrapped_cek).unwrap();

        let rek = RecipientEncryptedKey {
            rid: KeyAgreeRecipientIdentifier::RKeyId(RecipientKeyIdentifier {
                subject_key_identifier: &[
                    0xcd, 0x4b, 0xe3, 0x00, 0xeb, 0x86, 0x8e, 0xcb, 0x96, 0x45, 0xd7, 0x00, 0x45, 0xf6, 0x68, 0x04, 0x3d, 0x18, 0x25, 0xf7,
                ],
                date: None,
                other: None,
            }),
            encrypted_key: &wrapped_cek,
        };
        let reks = [rek];
        let kari = KeyAgreeRecipientInfo {
            version: 3,
            originator: OriginatorIdentifierOrKey::OriginatorKey(originator_key),
            ukm: None,
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Other(v.kea_oid.clone(), Some(wrap_alg_tlv.clone())),
            },
            recipient_encrypted_keys: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&reks)),
        };
        let ris = [RecipientInfo::KeyAgreeRecipientInfo(kari)];
        let enveloped = EnvelopedData {
            version: 2,
            originator_info: None,
            recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&ris)),
            encrypted_content_info: EncryptedContentInfo {
                content_type: PKCS7_DATA_OID.clone(),
                content_encryption_algorithm: AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: AlgorithmParameters::Aes128Cbc(iv),
                },
                encrypted_content: Some(&ciphertext),
            },
            unprotected_attrs: None,
        };
        let content_info = ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::EnvelopedData(asn1::Explicit::new(Box::new(enveloped))),
        };
        let der = asn1::write_single(&content_info).unwrap();

        let key_der = pem::parse(fs::read("tests/keys/test_x25519.key").unwrap()).unwrap().into_contents();
        let keys = smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() };
        verify_enveloped_roundtrip(&der, &keys, plaintext);

        let path = format!("tests/general/test_encrypted_{}.eml", v.name);
        write_fixture_eml(&path, &der, &format!("Test X25519 {}", v.name), "enveloped-data");
    }
}

fn gen_additional_fixtures() {
    gen_x25519_fixtures();
    #[cfg(feature = "decrypt-ccm")]
    gen_ccm_fixtures();
}

fn run_all() {
    generate_ed25519(&PathBuf::from("tests/general/ed25519.eml"));
    generate_ml_dsa_44_shake128(&PathBuf::from("tests/pq/ml-dsa-44-shake128.eml"));
    generate_ml_dsa_44_shake(&PathBuf::from("tests/pq/ml-dsa-44-shake.eml"));
    generate_ml_dsa_65_shake(&PathBuf::from("tests/pq/ml-dsa-65.eml"));
    generate_ml_dsa_87_shake(&PathBuf::from("tests/pq/ml-dsa-87.eml"));
    generate_no_message_digest(&PathBuf::from("tests/general/no-message-digest-attr.eml"));
    generate_no_auth_attrs(&PathBuf::from("tests/general/no-auth-attrs.eml"));
    gen_openssl_fixtures();
    gen_additional_fixtures();
    gen_multi_recipient_fixtures();
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Sign { command } => match command {
            SignCommands::Ed25519 { output } => generate_ed25519(output),
            SignCommands::MlDsa44Shake128 { output } => generate_ml_dsa_44_shake128(output),
            SignCommands::MlDsa44Shake { output } => generate_ml_dsa_44_shake(output),
            SignCommands::MlDsa65Shake { output } => generate_ml_dsa_65_shake(output),
            SignCommands::MlDsa87Shake { output } => generate_ml_dsa_87_shake(output),
            SignCommands::NoMessageDigest { output } => generate_no_message_digest(output),
            SignCommands::NoAuthAttrs { output } => generate_no_auth_attrs(output),
        },
        Commands::Encrypt { command } => match command {
            EncryptCommands::Openssl => gen_openssl_fixtures(),
            EncryptCommands::Additional => gen_additional_fixtures(),
            EncryptCommands::MultiRecipient => gen_multi_recipient_fixtures(),
        },
        Commands::Ocsp => gen_ocsp_stapling_fixtures(),
        Commands::All => run_all(),
    }
}

#[cfg(feature = "decrypt-ccm")]
fn gen_ccm_fixtures() {
    use ccm::{KeyInit, aead::AeadInOut};

    let plaintext = b"Content-Type: text/plain\r\n\r\nAES-CCM AuthEnvelopedData test\r\n";
    let key_der = pem::parse(fs::read("tests/keys/test_rsa.key").unwrap()).unwrap().into_contents();
    let cert_der = load_cert_der_for_fixtures("tests/keys/test_rsa.pem");

    for bits in [128, 256] {
        let key_len = bits / 8;
        let cek: Vec<u8> = random_bytes::<32>()[..key_len].to_vec();
        let nonce: [u8; 12] = random_bytes();

        let mut ciphertext = plaintext.to_vec();
        let tag = match key_len {
            16 => {
                type Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U12>;
                Ccm::new_from_slice(&cek).unwrap().encrypt_inout_detached((&nonce).into(), &[], (&mut ciphertext[..]).into()).unwrap()
            }
            32 => {
                type Ccm = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U12>;
                Ccm::new_from_slice(&cek).unwrap().encrypt_inout_detached((&nonce).into(), &[], (&mut ciphertext[..]).into()).unwrap()
            }
            _ => unreachable!(),
        };

        use rsa::pkcs8::DecodePrivateKey;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
        let encrypted_cek =
            rsa_key.to_public_key().encrypt(&mut rsa::rand_core::UnwrapErr(getrandom::SysRng), rsa::Pkcs1v15Encrypt, &cek).unwrap();
        let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
        let ias_der = asn1::write_single(&IssuerAndSerialNumber {
            issuer: cert.tbs_cert.issuer.clone(),
            serial_number: cert.tbs_cert.serial.clone(),
        })
        .unwrap();
        let ias: IssuerAndSerialNumber = asn1::parse_single(&ias_der).unwrap();
        let ktri = KeyTransRecipientInfo {
            version: 0,
            rid: RecipientIdentifier::IssuerAndSerialNumber(ias),
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::RSA(Some(())),
            },
            encrypted_key: &encrypted_cek,
        };
        let ktri_ri = RecipientInfo::KeyTransRecipientInfo(ktri);

        let ccm_params = CcmParameters { nonce: &nonce, icv_len: 16 };
        let cea_params = match key_len {
            16 => AlgorithmParameters::Aes128Ccm(ccm_params),
            32 => AlgorithmParameters::Aes256Ccm(ccm_params),
            _ => unreachable!(),
        };

        let ris = [ktri_ri];

        let auth_enveloped = AuthEnvelopedData {
            version: 0,
            originator_info: None,
            recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&ris)),
            auth_encrypted_content_info: EncryptedContentInfo {
                content_type: PKCS7_DATA_OID,
                content_encryption_algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: cea_params },
                encrypted_content: Some(&ciphertext),
            },
            auth_attrs: None,
            mac: tag.as_slice(),
            unauth_attrs: None,
        };

        let content_info = ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::AuthEnvelopedData(asn1::Explicit::new(Box::new(auth_enveloped))),
        };
        let der = asn1::write_single(&content_info).unwrap();

        // Verify round-trip
        let keys = smime::decrypt::DecryptionKeys { private_key_der: &key_der, recipient_cert_der: &cert_der, ..Default::default() };
        verify_auth_enveloped_roundtrip(&der, &keys, plaintext);

        let path = format!("tests/general/test_encrypted_ccm{}.eml", bits);
        write_fixture_eml(&path, &der, &format!("Test AES-{}-CCM", bits), "authEnveloped-data");
    }
}

/// Build KTRI (RSA key transport). Returns (ri_der, key_der, cert_der).
fn build_ktri(cek: &[u8], rsa_key_path: &str, rsa_cert_path: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::DecodePrivateKey;
    let key_der = pem::parse(fs::read(rsa_key_path).unwrap()).unwrap().into_contents();
    let cert_der = load_cert_der_for_fixtures(rsa_cert_path);
    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
    let encrypted_cek =
        rsa_key.to_public_key().encrypt(&mut rsa::rand_core::UnwrapErr(getrandom::SysRng), rsa::Pkcs1v15Encrypt, cek).unwrap();
    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let ias_der =
        asn1::write_single(&IssuerAndSerialNumber { issuer: cert.tbs_cert.issuer.clone(), serial_number: cert.tbs_cert.serial.clone() })
            .unwrap();
    let ias: IssuerAndSerialNumber = asn1::parse_single(&ias_der).unwrap();
    let ktri = KeyTransRecipientInfo {
        version: 0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(ias),
        key_encryption_algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::RSA(Some(())) },
        encrypted_key: &encrypted_cek,
    };
    let ri_der = asn1::write_single(&RecipientInfo::KeyTransRecipientInfo(ktri)).unwrap();
    (ri_der, key_der, cert_der)
}

fn build_kari_p256(cek: &[u8], ec_cert_path: &str) -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToSec1Point;

    let cert_der = load_cert_der_for_fixtures(ec_cert_path);
    let cert: smime::cryptography_x509::certificate::Certificate<'_> = asn1::parse_single(&cert_der).unwrap();
    let recipient_pk_bytes = cert.tbs_cert.spki.subject_public_key.as_bytes();
    let recipient_pk = p256::PublicKey::from_sec1_bytes(recipient_pk_bytes).unwrap();

    use p256::elliptic_curve::Generate;
    let eph_sk = p256::NonZeroScalar::generate();
    let eph_pk = p256::PublicKey::from_secret_scalar(&eph_sk);
    let eph_pk_bytes = eph_pk.to_sec1_point(false);

    let z = p256::ecdh::diffie_hellman(&eph_sk, recipient_pk.as_affine());

    let wrap_alg_der = asn1::write_single(&AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
    })
    .unwrap();

    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
        },
        entity_u_info: None,
        supp_pub_info: &0x00000080u32.to_be_bytes(),
    };
    let shared_info_der = asn1::write_single(&shared_info).unwrap();

    let mut kek = vec![0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(z.raw_secret_bytes(), &shared_info_der, &mut kek).unwrap();

    let mut wrapped_cek = vec![0u8; cek.len() + 8];
    aes_kw::KwAes128::new_from_slice(&kek).unwrap().wrap_key(cek, &mut wrapped_cek).unwrap();

    let ias_der =
        asn1::write_single(&IssuerAndSerialNumber { issuer: cert.tbs_cert.issuer.clone(), serial_number: cert.tbs_cert.serial.clone() })
            .unwrap();
    let ias: IssuerAndSerialNumber = asn1::parse_single(&ias_der).unwrap();

    let rek = RecipientEncryptedKey { rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias), encrypted_key: &wrapped_cek };
    let reks = [rek];
    let wrap_alg_tlv: asn1::Tlv = asn1::parse_single(&wrap_alg_der).unwrap();
    let originator_key = OriginatorPublicKey {
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::ECDSA(Some(EcParameters::NamedCurve(oid::EC_SECP256R1))),
        },
        public_key: asn1::BitString::new(eph_pk_bytes.as_bytes(), 0).unwrap(),
    };
    let kari = KeyAgreeRecipientInfo {
        version: 3,
        originator: OriginatorIdentifierOrKey::OriginatorKey(originator_key),
        ukm: None,
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::DH_STD_SHA256.clone(), Some(wrap_alg_tlv.clone())),
        },
        recipient_encrypted_keys: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&reks)),
    };
    let ri_der = asn1::write_single(&RecipientInfo::KeyAgreeRecipientInfo(kari)).unwrap();
    (ri_der, cert_der)
}

fn build_kari_x25519(cek: &[u8]) -> Vec<u8> {
    let eph_sk = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap()).unwrap(),
    );
    let eph_pk = x25519_dalek::PublicKey::from(&eph_sk);

    let recipient_sk = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(hex::decode("B8CA0426D44BADBF6D8749F4459804459D7177769689CBC1D6456D08DE843667").unwrap()).unwrap(),
    );
    let recipient_pk = x25519_dalek::PublicKey::from(&recipient_sk);
    let z = eph_sk.diffie_hellman(&recipient_pk);

    let wrap_alg_der = asn1::write_single(&AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
    })
    .unwrap();

    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::AES128_WRAP.clone(), None),
        },
        entity_u_info: None,
        supp_pub_info: &0x00000080u32.to_be_bytes(),
    };
    let shared_info_der = asn1::write_single(&shared_info).unwrap();

    let mut kek = vec![0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(z.as_bytes(), &shared_info_der, &mut kek).unwrap();

    let mut wrapped_cek = vec![0u8; cek.len() + 8];
    aes_kw::KwAes128::new_from_slice(&kek).unwrap().wrap_key(cek, &mut wrapped_cek).unwrap();

    let rek = RecipientEncryptedKey {
        rid: KeyAgreeRecipientIdentifier::RKeyId(RecipientKeyIdentifier {
            subject_key_identifier: &[
                0xcd, 0x4b, 0xe3, 0x00, 0xeb, 0x86, 0x8e, 0xcb, 0x96, 0x45, 0xd7, 0x00, 0x45, 0xf6, 0x68, 0x04, 0x3d, 0x18, 0x25, 0xf7,
            ],
            date: None,
            other: None,
        }),
        encrypted_key: &wrapped_cek,
    };
    let reks = [rek];
    let wrap_alg_tlv: asn1::Tlv = asn1::parse_single(&wrap_alg_der).unwrap();
    let originator_key = OriginatorPublicKey {
        algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::X25519 },
        public_key: asn1::BitString::new(eph_pk.as_bytes(), 0).unwrap(),
    };
    let kari = KeyAgreeRecipientInfo {
        version: 3,
        originator: OriginatorIdentifierOrKey::OriginatorKey(originator_key),
        ukm: None,
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::DH_STD_SHA256.clone(), Some(wrap_alg_tlv.clone())),
        },
        recipient_encrypted_keys: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&reks)),
    };
    asn1::write_single(&RecipientInfo::KeyAgreeRecipientInfo(kari)).unwrap()
}

fn build_kekri(cek: &[u8]) -> Vec<u8> {
    let kek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut wrapped_cek = vec![0u8; cek.len() + 8];
    aes_kw::KwAes256::new_from_slice(&kek).unwrap().wrap_key(cek, &mut wrapped_cek).unwrap();

    let kekri = KEKRecipientInfo {
        version: 4,
        kekid: KEKIdentifier { key_identifier: &[0x01, 0x02, 0x03, 0x04], date: None, other: None },
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::AES256_WRAP.clone(), None),
        },
        encrypted_key: &wrapped_cek,
    };
    asn1::write_single(&RecipientInfo::KEKRecipientInfo(kekri)).unwrap()
}

/// RFC 3211 §2.3.1 key wrap: format and double-encrypt a CEK.
/// Format: length(1) || check(3) || CEK || padding
/// Check = bitwise complement of first 3 bytes of CEK.
/// Returns (encrypted_key, iv).
fn rfc3211_wrap_cek(kek: &[u8], cek: &[u8]) -> (Vec<u8>, [u8; 16]) {
    assert!(cek.len() >= 3, "CEK must be at least 3 bytes for RFC 3211 check value");
    let block_size: usize = 16;
    let min_len = 4 + cek.len(); // 1 length + 3 check + CEK
    let mut padded_len = ((min_len + block_size - 1) / block_size) * block_size;
    if padded_len < 2 * block_size {
        padded_len = 2 * block_size;
    }
    let mut payload = vec![0u8; padded_len];
    payload[0] = cek.len() as u8;
    payload[1] = !cek[0];
    payload[2] = !cek[1];
    payload[3] = !cek[2];
    payload[4..4 + cek.len()].copy_from_slice(cek);
    if 4 + cek.len() < padded_len {
        let mut rng_buf = vec![0u8; padded_len - 4 - cek.len()];
        getrandom::fill(&mut rng_buf).unwrap();
        payload[4 + cek.len()..].copy_from_slice(&rng_buf);
    }
    let iv: [u8; 16] = random_bytes();
    // RFC 3211 §2.3.1: encrypt, then encrypt again without resetting IV
    macro_rules! wrap_2pass {
        ($cipher:ty) => {{
            // Pass 1: CBC encrypt with IV
            cbc::Encryptor::<$cipher>::new_from_slices(kek, &iv)
                .unwrap()
                .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut payload, padded_len)
                .unwrap();
            // Pass 2: CBC encrypt again; IV = last block of pass 1 output
            let pass2_iv: [u8; 16] = payload[padded_len - block_size..].try_into().unwrap();
            cbc::Encryptor::<$cipher>::new_from_slices(kek, &pass2_iv)
                .unwrap()
                .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut payload, padded_len)
                .unwrap();
        }};
    }
    match kek.len() {
        16 => wrap_2pass!(aes::Aes128),
        24 => wrap_2pass!(aes::Aes192),
        32 => wrap_2pass!(aes::Aes256),
        _ => panic!("invalid KEK length"),
    }
    (payload, iv)
}

const PWRI_KEK_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 16, 3, 9);

fn build_pwri(cek: &[u8], password: &str) -> Vec<u8> {
    let salt: [u8; 16] = random_bytes();
    let iterations: u32 = 100_000;
    let kek_len: usize = 32; // AES-256

    let mut kek = vec![0u8; kek_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, iterations, &mut kek);

    let (encrypted_key, wrap_iv) = rfc3211_wrap_cek(&kek, cek);

    // Inner cipher algorithm (AES-256-CBC with the wrap IV)
    let inner_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Aes256Cbc(wrap_iv) };
    let inner_alg_der = asn1::write_single(&inner_alg).unwrap();
    let inner_alg_tlv: asn1::Tlv = asn1::parse_single(&inner_alg_der).unwrap();

    let hmac_sha256_alg =
        AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::HmacWithSha256(Some(())) };

    let pbkdf2_params =
        PBKDF2Params { salt: &salt, iteration_count: iterations as u64, key_length: Some(kek_len as u64), prf: Box::new(hmac_sha256_alg) };
    let kda = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Pbkdf2(pbkdf2_params) };

    let pwri = PasswordRecipientInfo {
        version: 0,
        key_derivation_algorithm: Some(kda),
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(PWRI_KEK_OID.clone(), Some(inner_alg_tlv)),
        },
        encrypted_key: &encrypted_key,
    };
    asn1::write_single(&RecipientInfo::PasswordRecipientInfo(pwri)).unwrap()
}

fn build_enveloped_data_der(ris_der: &[Vec<u8>], ciphertext: &[u8], iv: &[u8; 16], version: u8) -> Vec<u8> {
    let ris: Vec<RecipientInfo> = ris_der.iter().map(|d| asn1::parse_single(d).unwrap()).collect();
    let enveloped = EnvelopedData {
        version,
        originator_info: None,
        recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&ris)),
        encrypted_content_info: EncryptedContentInfo {
            content_type: PKCS7_DATA_OID.clone(),
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Aes256Cbc(*iv),
            },
            encrypted_content: Some(ciphertext),
        },
        unprotected_attrs: None,
    };
    let content_info = ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::EnvelopedData(asn1::Explicit::new(Box::new(enveloped))),
    };
    asn1::write_single(&content_info).unwrap()
}

fn gen_multi_recipient_fixtures() {
    let plaintext = b"Content-Type: text/plain\r\n\r\nMulti-recipient-type test\r\n";

    // Fixture 1: KTRI + KARI(P-256) + KARI(X25519) + KEKRI + PWRI
    {
        let cek: [u8; 32] = random_bytes();
        let iv: [u8; 16] = random_bytes();
        let ciphertext = encrypt_aes_cbc(&cek, &iv, plaintext);

        let (ktri_der, rsa_key_der, rsa_cert_der) = build_ktri(&cek, "tests/keys/test_rsa.key", "tests/keys/test_rsa.pem");
        let (kari_p256_der, p256_cert_der) = build_kari_p256(&cek, "tests/keys/test_p256.pem");
        let kari_x25519_der = build_kari_x25519(&cek);
        let kekri_der = build_kekri(&cek);
        let pwri_der = build_pwri(&cek, "zone.eu");

        let ris_der = vec![ktri_der, kari_p256_der, kari_x25519_der, kekri_der, pwri_der];
        let der = build_enveloped_data_der(&ris_der, &ciphertext, &iv, 3);

        // Verify each recipient type can decrypt
        let rsa_keys =
            smime::decrypt::DecryptionKeys { private_key_der: &rsa_key_der, recipient_cert_der: &rsa_cert_der, ..Default::default() };
        verify_enveloped_roundtrip(&der, &rsa_keys, plaintext);

        let p256_key_der = pem::parse(fs::read("tests/keys/test_p256.key").unwrap()).unwrap().into_contents();
        let p256_keys =
            smime::decrypt::DecryptionKeys { private_key_der: &p256_key_der, recipient_cert_der: &p256_cert_der, ..Default::default() };
        verify_enveloped_roundtrip(&der, &p256_keys, plaintext);

        let x25519_key_der = pem::parse(fs::read("tests/keys/test_x25519.key").unwrap()).unwrap().into_contents();
        let x25519_cert_der = load_cert_der_for_fixtures("tests/keys/test_x25519.pem");
        let x25519_keys =
            smime::decrypt::DecryptionKeys { private_key_der: &x25519_key_der, recipient_cert_der: &x25519_cert_der, ..Default::default() };
        verify_enveloped_roundtrip(&der, &x25519_keys, plaintext);

        let kek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let kek_keys = smime::decrypt::DecryptionKeys { kek: Some(&kek), ..Default::default() };
        verify_enveloped_roundtrip(&der, &kek_keys, plaintext);

        let pwd_keys = smime::decrypt::DecryptionKeys { password: Some("zone.eu"), ..Default::default() };
        verify_enveloped_roundtrip(&der, &pwd_keys, plaintext);

        write_fixture_eml("tests/general/test_encrypted_multi_type_all.eml", &der, "Test KTRI+KARI+KEKRI+PWRI", "enveloped-data");
    }

    // Fixture 2: KTRI + PWRI
    {
        let cek: [u8; 32] = random_bytes();
        let iv: [u8; 16] = random_bytes();
        let ciphertext = encrypt_aes_cbc(&cek, &iv, plaintext);

        let (ktri_der, rsa_key_der, rsa_cert_der) = build_ktri(&cek, "tests/keys/test_rsa.key", "tests/keys/test_rsa.pem");
        let pwri_der = build_pwri(&cek, "zone.eu");

        let ris_der = vec![ktri_der, pwri_der];
        let der = build_enveloped_data_der(&ris_der, &ciphertext, &iv, 3);

        let rsa_keys =
            smime::decrypt::DecryptionKeys { private_key_der: &rsa_key_der, recipient_cert_der: &rsa_cert_der, ..Default::default() };
        verify_enveloped_roundtrip(&der, &rsa_keys, plaintext);

        let pwd_keys = smime::decrypt::DecryptionKeys { password: Some("zone.eu"), ..Default::default() };
        verify_enveloped_roundtrip(&der, &pwd_keys, plaintext);

        write_fixture_eml("tests/general/test_encrypted_multi_type_rsa_pwri.eml", &der, "Test KTRI+PWRI", "enveloped-data");
    }
}

fn openssl_cms_encrypt(plaintext: &[u8], cipher: &str, recip_certs: &[&str], keyopts: &[&str], extra_args: &[&str]) -> Vec<u8> {
    use std::process::Command;
    let mut cmd = Command::new("openssl");
    cmd.args(["cms", "-encrypt", cipher, "-outform", "der"]);
    for cert in recip_certs {
        cmd.args(["-recip", cert]);
    }
    for opt in keyopts {
        cmd.args(["-keyopt", opt]);
    }
    cmd.args(extra_args);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to run openssl");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "openssl cms -encrypt failed: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

fn openssl_cms_encrypt_pwri(plaintext: &[u8], cipher: &str, password: &str) -> Vec<u8> {
    use std::process::Command;
    let mut cmd = Command::new("openssl");
    cmd.args(["cms", "-encrypt", cipher, "-outform", "der", "-pwri_password", password]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to run openssl");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "openssl cms -encrypt (pwri) failed: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

fn openssl_cms_encrypt_kek(plaintext: &[u8], cipher: &str, key_hex: &str, key_id_hex: &str) -> Vec<u8> {
    use std::process::Command;
    let mut cmd = Command::new("openssl");
    cmd.args(["cms", "-encrypt", cipher, "-outform", "der", "-secretkey", key_hex, "-secretkeyid", key_id_hex]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to run openssl");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "openssl cms -encrypt (kek) failed: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

fn openssl_cms_sign(plaintext: &[u8], signer_cert: &str, signer_key: &str, md: &str, keyopts: &[&str]) -> Vec<u8> {
    use std::process::Command;
    let mut cmd = Command::new("openssl");
    cmd.args(["cms", "-sign", "-outform", "der", "-nodetach", "-signer", signer_cert, "-inkey", signer_key, "-md", md]);
    for opt in keyopts {
        cmd.args(["-keyopt", opt]);
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to run openssl");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "openssl cms -sign failed: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

fn gen_openssl_fixtures() {
    let plaintext = b"Content-Type: text/plain\r\n\r\nOpenSSL-generated test fixture\r\n";
    let rsa_cert = "tests/keys/test_rsa.pem";
    let ec256_cert = "tests/keys/test_p256.pem";
    let ec384_cert = "tests/keys/test_p384.pem";
    let ec521_cert = "tests/keys/test_p521.pem";

    struct Fixture {
        path: &'static str,
        cipher: &'static str,
        certs: Vec<&'static str>,
        keyopts: Vec<&'static str>,
        extra_args: Vec<&'static str>,
        smime_type: &'static str,
        subject: &'static str,
    }

    let fixtures = [
        // RSA PKCS#1v1.5 + AES-CBC key sizes
        Fixture {
            path: "tests/general/test_encrypted_rsa_aes256.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test AES-256-CBC RSA PKCS1",
        },
        Fixture {
            path: "tests/general/test_encrypted_rsa_aes128.eml",
            cipher: "-aes-128-cbc",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test AES-128-CBC RSA PKCS1",
        },
        Fixture {
            path: "tests/general/test_encrypted_rsa_aes192.eml",
            cipher: "-aes-192-cbc",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test AES-192-CBC RSA PKCS1",
        },
        // RSA OAEP + hash variants
        Fixture {
            path: "tests/general/test_encrypted_oaep.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha256"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test OAEP SHA-256",
        },
        Fixture {
            path: "tests/general/test_encrypted_oaep384.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha384"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test OAEP SHA-384",
        },
        Fixture {
            path: "tests/general/test_encrypted_oaep512.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha512"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test OAEP SHA-512",
        },
        Fixture {
            path: "tests/general/test_encrypted_oaep_sha1.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha1"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test OAEP SHA-1",
        },
        Fixture {
            path: "tests/general/test_encrypted_oaep_aes128.eml",
            cipher: "-aes-128-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha256"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test AES-128 OAEP",
        },
        Fixture {
            path: "tests/general/test_encrypted_oaep_aes192.eml",
            cipher: "-aes-192-cbc",
            certs: vec![rsa_cert],
            keyopts: vec!["rsa_padding_mode:oaep", "rsa_oaep_md:sha256"],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test AES-192 OAEP",
        },
        // ECDH (P-256, P-384, P-521)
        Fixture {
            path: "tests/general/test_encrypted_ecdh.eml",
            cipher: "-aes-256-cbc",
            certs: vec![ec256_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test ECDH P-256",
        },
        Fixture {
            path: "tests/general/test_encrypted_ecdh_p384.eml",
            cipher: "-aes-256-cbc",
            certs: vec![ec384_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test ECDH P-384",
        },
        Fixture {
            path: "tests/general/test_encrypted_ecdh_p521.eml",
            cipher: "-aes-256-cbc",
            certs: vec![ec521_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test ECDH P-521",
        },
        // Multi-recipient (RSA + EC in one message)
        Fixture {
            path: "tests/general/test_encrypted_multi_recipient.eml",
            cipher: "-aes-256-cbc",
            certs: vec![rsa_cert, ec256_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test Multi-Recipient RSA+EC",
        },
        // AES-GCM (AuthEnvelopedData)
        Fixture {
            path: "tests/general/test_encrypted_gcm128.eml",
            cipher: "-aes-128-gcm",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "authEnveloped-data",
            subject: "Test AES-128-GCM",
        },
        Fixture {
            path: "tests/general/test_encrypted_gcm192.eml",
            cipher: "-aes-192-gcm",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "authEnveloped-data",
            subject: "Test AES-192-GCM",
        },
        Fixture {
            path: "tests/general/test_encrypted_gcm256.eml",
            cipher: "-aes-256-gcm",
            certs: vec![rsa_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "authEnveloped-data",
            subject: "Test AES-256-GCM",
        },
        // AES-GCM with ECDH recipient
        Fixture {
            path: "tests/general/test_encrypted_gcm256_ecdh.eml",
            cipher: "-aes-256-gcm",
            certs: vec![ec256_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "authEnveloped-data",
            subject: "Test AES-256-GCM ECDH",
        },
        // ECDH with different content cipher key sizes
        Fixture {
            path: "tests/general/test_encrypted_ecdh_aes128.eml",
            cipher: "-aes-128-cbc",
            certs: vec![ec256_cert],
            keyopts: vec![],
            extra_args: vec![],
            smime_type: "enveloped-data",
            subject: "Test ECDH P-256 AES-128",
        },
        // ECDH with AES-192-WRAP and AES-256-WRAP
        Fixture {
            path: "tests/general/test_encrypted_ecdh_wrap192.eml",
            cipher: "-aes-256-cbc",
            certs: vec![ec256_cert],
            keyopts: vec![],
            extra_args: vec!["-wrap", "aes192-wrap"],
            smime_type: "enveloped-data",
            subject: "Test ECDH AES-192-WRAP",
        },
        Fixture {
            path: "tests/general/test_encrypted_ecdh_wrap256.eml",
            cipher: "-aes-256-cbc",
            certs: vec![ec256_cert],
            keyopts: vec![],
            extra_args: vec!["-wrap", "aes256-wrap"],
            smime_type: "enveloped-data",
            subject: "Test ECDH AES-256-WRAP",
        },
    ];

    for f in &fixtures {
        let der = openssl_cms_encrypt(plaintext, f.cipher, &f.certs, &f.keyopts, &f.extra_args);
        write_fixture_eml(f.path, &der, f.subject, f.smime_type);
    }

    {
        let der = openssl_cms_encrypt_pwri(plaintext, "-aes-256-cbc", "zone.eu");
        write_fixture_eml("tests/general/test_encrypted_pwri.eml", &der, "Test PWRI", "enveloped-data");
    }

    // Ed448 signature
    let sign_plaintext = b"Content-Type: text/plain\r\n\r\nHello from Ed448!\r\n";
    let ed448_der = openssl_cms_sign(sign_plaintext, "tests/keys/test_ed448.pem", "tests/keys/test_ed448.key", "shake256", &[]);
    write_fixture_eml("tests/general/test_sig_ed448.eml", &ed448_der, "Test Ed448", "signed-data");

    // RSA PKCS#1v1.5 signatures with SHA-256/384/512
    let sign_plain = b"Content-Type: text/plain\r\n\r\nRSA signature test\r\n";
    for (md, name) in [("sha256", "rsa_sha256"), ("sha384", "rsa_sha384"), ("sha512", "rsa_sha512")] {
        let der = openssl_cms_sign(sign_plain, rsa_cert, "tests/keys/test_rsa.key", md, &[]);
        write_fixture_eml(&format!("tests/general/test_sig_{name}.eml"), &der, &format!("Test RSA {}", md.to_uppercase()), "signed-data");
    }

    // RSA-PSS signatures with SHA-384/512
    for (md, salt, name) in [("sha384", "48", "rsa_pss_sha384"), ("sha512", "64", "rsa_pss_sha512")] {
        let der = openssl_cms_sign(
            sign_plain,
            rsa_cert,
            "tests/keys/test_rsa.key",
            md,
            &["rsa_padding_mode:pss", &format!("rsa_pss_saltlen:{salt}")],
        );
        write_fixture_eml(
            &format!("tests/general/test_sig_{name}.eml"),
            &der,
            &format!("Test RSA-PSS {}", md.to_uppercase()),
            "signed-data",
        );
    }

    // SHA3
    for (md, name) in [("sha3-256", "sha3_256"), ("sha3-384", "sha3_384"), ("sha3-512", "sha3_512")] {
        let der = openssl_cms_sign(sign_plain, rsa_cert, "tests/keys/test_rsa.key", md, &[]);
        write_fixture_eml(&format!("tests/general/test_sig_rsa_digest_{name}.eml"), &der, &format!("Test RSA digest {md}"), "signed-data");
    }

    // KEKRI
    let kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let kekri_der = openssl_cms_encrypt_kek(plaintext, "-aes-256-cbc", kek_hex, "01020304");
    write_fixture_eml("tests/general/test_encrypted_kekri.eml", &kekri_der, "Test KEKRI", "enveloped-data");
}

fn load_cert_der_for_fixtures(path: &str) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    match pem::parse(&bytes) {
        Ok(p) => p.into_contents(),
        Err(_) => bytes,
    }
}

// Stapled-OCSP fixtures: a root CA that issued an S/MIME leaf, with an OCSP staple
// in SignedData.crls. Dates are fixed so fixtures are reproducible.
use smime::cryptography_x509::certificate::Certificate as FixtureCert;
use smime::cryptography_x509::extensions::{BasicConstraints, Extension};
use smime::cryptography_x509::ocsp_req::CertID;
use smime::cryptography_x509::ocsp_resp::{
    BasicOCSPResponse, CertStatus, OCSPResponse, ResponderId, Response, ResponseBytes, ResponseData, RevokedInfo, SingleResponse,
};

fn rsa_signer(key_path: &str) -> impl Fn(&[u8]) -> Vec<u8> {
    use rsa::pkcs8::DecodePrivateKey;
    let key_pem = fs::read_to_string(key_path).unwrap_or_else(|_| panic!("read {}", key_path));
    let sk = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem).expect("parse RSA key");
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sk);
    move |data: &[u8]| {
        use signature::{SignatureEncoding, Signer};
        signer.sign(data).to_vec()
    }
}

/// Hash algorithm a fixture's OCSP `CertID` is built with.
#[derive(Clone, Copy)]
enum CertIdHash {
    Sha1,
    Sha256,
}

fn rsa_sha256_alg() -> AlgorithmIdentifier<'static> {
    AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::RsaWithSha256(Some(())) }
}

fn validity_utc(nb: (u16, u8, u8), na: (u16, u8, u8)) -> Validity {
    let mk = |(y, m, d): (u16, u8, u8)| Time::UtcTime(asn1::UtcTime::new(asn1::DateTime::new(y, m, d, 0, 0, 0).unwrap()).unwrap());
    Validity { not_before: mk(nb), not_after: mk(na) }
}

fn gen_time(y: u16, m: u8, d: u8) -> asn1::X509GeneralizedTime {
    asn1::X509GeneralizedTime::new(asn1::DateTime::new(y, m, d, 0, 0, 0).unwrap()).unwrap()
}

fn spki_der_of(cert_pem_path: &str) -> Vec<u8> {
    let cert_der = load_cert_der_for_fixtures(cert_pem_path);
    let cert: FixtureCert<'_> = asn1::parse_single(&cert_der).unwrap();
    asn1::write_single(&cert.tbs_cert.spki).unwrap()
}

fn pubkey_bits_of(cert_pem_path: &str) -> Vec<u8> {
    let cert_der = load_cert_der_for_fixtures(cert_pem_path);
    let cert: FixtureCert<'_> = asn1::parse_single(&cert_der).unwrap();
    cert.tbs_cert.spki.subject_public_key.as_bytes().to_vec()
}

// Extension value (extnValue inner DER) builders.
fn ev_basic_constraints_ca() -> Vec<u8> {
    asn1::write_single(&BasicConstraints { ca: true, path_length: None }).unwrap()
}
fn ev_key_usage_ca() -> Vec<u8> {
    // digitalSignature (bit 0) + keyCertSign (bit 5) -> 0x84, with 2 unused trailing bits.
    asn1::write_single(&asn1::BitString::new(&[0x84], 2).unwrap()).unwrap()
}
fn ev_eku(oids: &[asn1::ObjectIdentifier]) -> Vec<u8> {
    asn1::write_single(&asn1::SequenceOfWriter::new(oids.to_vec())).unwrap()
}
fn ev_null() -> Vec<u8> {
    asn1::write_single(&()).unwrap()
}

/// Build an X.509v3 certificate, reusing the public key from `spki_der` and signing with `sign`.
fn build_cert(
    issuer_name_der: &[u8],
    subject_cn: &str,
    spki_der: &[u8],
    validity: Validity,
    extensions: &[(asn1::ObjectIdentifier, bool, Vec<u8>)],
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut serial = random_bytes::<16>().to_vec();
    serial[0] &= 0x7F;
    if serial[0] == 0 {
        serial[0] = 1;
    }

    let subject_name_der = build_name_der(subject_cn);
    let sig_alg = rsa_sha256_alg();

    let spki_with_tlv: WithTlv<'_, SubjectPublicKeyInfo<'_>> = asn1::parse_single(spki_der).unwrap();
    let issuer: name::NameReadable<'_> = asn1::parse_single(issuer_name_der).unwrap();
    let subject: name::NameReadable<'_> = asn1::parse_single(&subject_name_der).unwrap();

    let ext_objs: Vec<Extension<'_>> =
        extensions.iter().map(|(oid, crit, val)| Extension { extn_id: oid.clone(), critical: *crit, extn_value: val.as_slice() }).collect();
    let raw_extensions = Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(ext_objs));

    let tbs = TbsCertificate {
        version: 2,
        serial: asn1::BigInt::new(&serial).unwrap(),
        signature_alg: sig_alg.clone(),
        issuer: Asn1ReadableOrWritable::new_read(issuer),
        validity,
        subject: Asn1ReadableOrWritable::new_read(subject),
        spki: spki_with_tlv,
        issuer_unique_id: None,
        subject_unique_id: None,
        raw_extensions: Some(raw_extensions),
    };

    let tbs_der = asn1::write_single(&tbs).unwrap();
    let signature_bytes = sign(&tbs_der);
    let sig_bs = asn1::OwnedBitString::new(signature_bytes, 0).unwrap();

    let tbs_tlv: asn1::Tlv<'_> = asn1::parse_single(&tbs_der).unwrap();
    let cert_der = asn1::write_single(&asn1::SequenceWriter::new(&|w| -> asn1::WriteResult {
        w.write_element(&tbs_tlv)?;
        w.write_element(&sig_alg)?;
        w.write_element(&sig_bs)?;
        Ok(())
    }))
    .unwrap();

    (cert_der, serial, subject_name_der)
}

/// Build a DER `OCSPResponse` carrying one SingleResponse for the leaf.
#[allow(clippy::too_many_arguments)]
fn build_ocsp_response(
    leaf_issuer_name_der: &[u8],
    issuer_pubkey_bits: &[u8],
    leaf_serial: &[u8],
    responder_name_der: &[u8],
    good: bool,
    this_update: (u16, u8, u8),
    next_update: Option<(u16, u8, u8)>,
    embedded_certs: Vec<FixtureCert<'_>>,
    cert_id_hash: CertIdHash,
    ocsp_sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let (hash_alg_params, issuer_name_hash, issuer_key_hash) = match cert_id_hash {
        CertIdHash::Sha1 => (
            AlgorithmParameters::Sha1(Some(())),
            smime::ocsp::sha1_of(leaf_issuer_name_der).to_vec(),
            smime::ocsp::sha1_of(issuer_pubkey_bits).to_vec(),
        ),
        CertIdHash::Sha256 => (
            AlgorithmParameters::Sha256(Some(())),
            smime::ocsp::sha256_of(leaf_issuer_name_der).to_vec(),
            smime::ocsp::sha256_of(issuer_pubkey_bits).to_vec(),
        ),
    };

    let cert_id = CertID {
        hash_algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: hash_alg_params },
        issuer_name_hash: &issuer_name_hash,
        issuer_key_hash: &issuer_key_hash,
        serial_number: asn1::BigInt::new(leaf_serial).unwrap(),
    };

    let revoked_info = RevokedInfo { revocation_time: gen_time(this_update.0, this_update.1, this_update.2), revocation_reason: None };
    let single = SingleResponse {
        cert_id,
        cert_status: if good { CertStatus::Good(()) } else { CertStatus::Revoked(revoked_info) },
        this_update: gen_time(this_update.0, this_update.1, this_update.2),
        next_update: next_update.map(|(y, m, d)| gen_time(y, m, d)),
        raw_single_extensions: None,
    };

    let responder_name: name::NameReadable<'_> = asn1::parse_single(responder_name_der).unwrap();
    let tbs_response_data = ResponseData {
        version: 0,
        responder_id: ResponderId::ByName(Asn1ReadableOrWritable::new_read(responder_name)),
        produced_at: gen_time(this_update.0, this_update.1, this_update.2),
        responses: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(vec![single])),
        raw_response_extensions: None,
    };

    let tbs_der = asn1::write_single(&tbs_response_data).unwrap();
    let signature = ocsp_sign(&tbs_der);

    let certs =
        if embedded_certs.is_empty() { None } else { Some(Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(embedded_certs))) };

    let basic = BasicOCSPResponse {
        tbs_response_data,
        signature_algorithm: rsa_sha256_alg(),
        signature: asn1::BitString::new(&signature, 0).unwrap(),
        certs,
    };

    let ocsp_resp = OCSPResponse {
        response_status: asn1::Enumerated::new(0),
        response_bytes: Some(ResponseBytes {
            response_type: asn1::DefinedByMarker::marker(),
            response: Response::Basic(asn1::OctetStringEncoded::new(basic)),
        }),
    };

    asn1::write_single(&ocsp_resp).unwrap()
}

/// Build a CMS SignedData: leaf signs `content`; embeds leaf+root+extra certs (responder or
/// intermediate) and the OCSP staples.
#[allow(clippy::too_many_arguments)]
fn build_stapled_cms(
    leaf_der: &[u8],
    root_der: &[u8],
    extra_cert_ders: &[&[u8]],
    leaf_serial: &[u8],
    signer_issuer_name_der: &[u8],
    ocsp_resp_ders: &[&[u8]],
    content: &[u8],
    leaf_sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let digest_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha256(Some(())) };
    let sig_alg = rsa_sha256_alg();
    let content_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(content).to_vec()
    };

    let data_oid_der = asn1::write_single(&PKCS7_DATA_OID).unwrap();
    let data_oid_tlv: asn1::Tlv<'_> = asn1::parse_single(&data_oid_der).unwrap();
    let content_type_attr = csr::Attribute {
        type_id: oid::CONTENT_TYPE_OID,
        values: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([RawTlv::new(data_oid_tlv.tag(), data_oid_tlv.data())])),
    };
    let digest_octet_tag = <&[u8] as asn1::SimpleAsn1Readable>::TAG;
    let message_digest_attr = csr::Attribute {
        type_id: oid::MESSAGE_DIGEST_OID,
        values: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([RawTlv::new(digest_octet_tag, &content_hash)])),
    };
    let attrs_set = asn1::SetOfWriter::new(vec![content_type_attr, message_digest_attr]);
    let attrs_set_der = asn1::write_single(&attrs_set).unwrap();
    let attrs_signature = leaf_sign(&attrs_set_der);
    let parsed_attrs: asn1::SetOf<'_, csr::Attribute<'_>> = asn1::parse_single(&attrs_set_der).unwrap();

    let leaf_cert: FixtureCert<'_> = asn1::parse_single(leaf_der).unwrap();
    let root_cert: FixtureCert<'_> = asn1::parse_single(root_der).unwrap();
    let signer_issuer: name::NameReadable<'_> = asn1::parse_single(signer_issuer_name_der).unwrap();

    let signer_info = SignerInfo {
        version: 1,
        issuer_and_serial_number: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Asn1ReadableOrWritable::new_read(signer_issuer),
            serial_number: asn1::BigInt::new(leaf_serial).unwrap(),
        }),
        digest_algorithm: digest_alg.clone(),
        authenticated_attributes: Some(Asn1ReadableOrWritable::new_read(parsed_attrs)),
        digest_encryption_algorithm: sig_alg,
        encrypted_digest: &attrs_signature,
        unauthenticated_attributes: None,
    };

    let mut cert_choices = vec![CertificateChoices::Certificate(leaf_cert), CertificateChoices::Certificate(root_cert)];
    for &der in extra_cert_ders {
        cert_choices.push(CertificateChoices::Certificate(asn1::parse_single::<FixtureCert<'_>>(der).unwrap()));
    }

    let crl_choices: Vec<RevocationInfoChoice<'_>> = ocsp_resp_ders
        .iter()
        .map(|&der| {
            let ocsp_tlv: asn1::Tlv<'_> = asn1::parse_single(der).unwrap();
            RevocationInfoChoice::Other(OtherRevocationInfoFormat { other_rev_info_format: oid::RI_OCSP_OID, other_rev_info: ocsp_tlv })
        })
        .collect();

    let digest_algs = [digest_alg];
    let signer_infos = [signer_info];

    let signed_data = SignedData {
        version: 5,
        digest_algorithms: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&digest_algs)),
        content_info: ContentInfo {
            content_type: asn1::DefinedByMarker::marker(),
            content: Content::Data(Some(asn1::Explicit::new(content))),
        },
        certificates: Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(cert_choices))),
        crls: Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(crl_choices))),
        signer_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&signer_infos)),
    };

    let content_info = ContentInfo {
        content_type: asn1::DefinedByMarker::marker(),
        content: Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };

    asn1::write_single(&content_info).unwrap()
}

fn write_pem_cert(dir: &std::path::Path, name: &str, der: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    fs::write(&path, pem::encode_config(&pem::Pem::new("CERTIFICATE", der.to_vec()), config)).unwrap();
    path
}

/// Produce a DER `OCSPResponse` for `leaf_serial` with `openssl ocsp` acting as an independent
/// responder: an `index.txt` marks the serial valid or revoked, then the response is signed by
/// `signer_cert`/`signer_key` (the issuer itself, or a delegated responder). `-rmd sha256` keeps
/// the response signature off SHA-1 (rejected by check_algorithm_permitted); `-ndays 36500` puts
/// `nextUpdate` far enough out that the committed fixture never goes stale.
fn openssl_ocsp_response(
    dir: &std::path::Path,
    ca_pem: &std::path::Path,
    leaf_pem: &std::path::Path,
    leaf_serial: &[u8],
    leaf_not_after: &str,
    revoked: bool,
    signer_cert: &std::path::Path,
    signer_key: &str,
) -> Vec<u8> {
    use std::process::Command;
    let serial: String = leaf_serial.iter().map(|b| format!("{b:02X}")).collect();
    let line = if revoked {
        format!("R\t{leaf_not_after}\t240115000000Z\t{serial}\tunknown\t/CN=leaf\n")
    } else {
        format!("V\t{leaf_not_after}\t\t{serial}\tunknown\t/CN=leaf\n")
    };
    let index = dir.join("index.txt");
    fs::write(&index, line).unwrap();
    let req = dir.join("req.der");
    let resp = dir.join("resp.der");

    let out = Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer")
        .arg(ca_pem)
        .arg("-cert")
        .arg(leaf_pem)
        .arg("-reqout")
        .arg(&req)
        .arg("-no_nonce")
        .output()
        .expect("run openssl ocsp -reqout");
    assert!(out.status.success(), "openssl ocsp -reqout failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = Command::new("openssl")
        .arg("ocsp")
        .arg("-index")
        .arg(&index)
        .arg("-CA")
        .arg(ca_pem)
        .arg("-rsigner")
        .arg(signer_cert)
        .arg("-rkey")
        .arg(signer_key)
        .arg("-rmd")
        .arg("sha256")
        .arg("-reqin")
        .arg(&req)
        .arg("-respout")
        .arg(&resp)
        .arg("-ndays")
        .arg("36500")
        .arg("-no_nonce")
        .output()
        .expect("run openssl ocsp responder");
    assert!(out.status.success(), "openssl ocsp responder failed: {}", String::from_utf8_lossy(&out.stderr));

    fs::read(&resp).unwrap()
}

fn gen_ocsp_stapling_fixtures() {
    fs::create_dir_all("tests/ocsp").unwrap();

    // Keys: root CA = test_rsa_sign, leaf & delegated responder = test_rsa.
    let root_sign = rsa_signer("tests/keys/test_rsa_sign.key");
    let leaf_sign = rsa_signer("tests/keys/test_rsa.key");
    let root_spki = spki_der_of("tests/keys/test_rsa_sign.pem");
    let root_pubkey_bits = pubkey_bits_of("tests/keys/test_rsa_sign.pem");
    let leaf_spki = spki_der_of("tests/keys/test_rsa.pem");
    let leaf_pubkey_bits = pubkey_bits_of("tests/keys/test_rsa.pem");

    // Self-signed root CA, valid 2024-01-01 .. 2035-01-01.
    let root_name_der = build_name_der("Test Stapling Root CA");
    let (root_der, _root_serial, root_subject_der) = build_cert(
        &root_name_der,
        "Test Stapling Root CA",
        &root_spki,
        validity_utc((2024, 1, 1), (2035, 1, 1)),
        &[(oid::BASIC_CONSTRAINTS_OID, true, ev_basic_constraints_ca()), (oid::KEY_USAGE_OID, true, ev_key_usage_ca())],
        &root_sign,
    );
    // Trust anchor for the tests, include_str!'d by tests/ocsp.rs and tests/ocsp_interop.rs.
    write_pem_cert(std::path::Path::new("tests/ocsp"), "root_ca.pem", &root_der);

    // Valid leaf (2024-01-01 .. 2035-01-01), emailProtection, issued by root.
    let (leaf_der, leaf_serial, _leaf_subject_der) = build_cert(
        &root_subject_der,
        "Anu Allkirjastaja",
        &leaf_spki,
        validity_utc((2024, 1, 1), (2035, 1, 1)),
        &[(oid::EXTENDED_KEY_USAGE_OID, false, ev_eku(&[oid::EKU_EMAIL_PROTECTION_OID]))],
        &root_sign,
    );

    // Expired leaf (2024-01-01 .. 2024-02-01), same key/issuer, for the regression below.
    let (expired_leaf_der, expired_leaf_serial, _) = build_cert(
        &root_subject_der,
        "Anu Allkirjastaja",
        &leaf_spki,
        validity_utc((2024, 1, 1), (2024, 2, 1)),
        &[(oid::EXTENDED_KEY_USAGE_OID, false, ev_eku(&[oid::EKU_EMAIL_PROTECTION_OID]))],
        &root_sign,
    );

    let content = b"Content-Type: text/plain\r\n\r\nStapled OCSP test\r\n";
    let this_update = (2024, 1, 15);
    // nextUpdate within the issuer/responder validity window, so staples that should stay
    // honored do not trip the relying-party freshness cap for nextUpdate-less responses.
    let next_update = Some((2035, 1, 1));

    let write = |name: &str, cms: &[u8]| write_fixture_eml(format!("tests/ocsp/{name}.eml"), cms, "Test Stapled OCSP", "signed-data");

    // 1. Good OCSP signed directly by the issuing root -> recorded as good, stays trusted.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            true,
            this_update,
            next_update,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_issuer_good", &cms);
    }

    // 2. Revoked OCSP signed by the issuing root -> certificate invalid even though valid.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            false,
            this_update,
            next_update,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_issuer_revoked", &cms);
    }

    // 3. Good OCSP signed by a delegated, authorized responder -> recorded as good.
    {
        let (responder_der, _rs, responder_subject_der) = build_cert(
            &root_subject_der,
            "Test OCSP Responder",
            &leaf_spki,
            validity_utc((2024, 1, 1), (2035, 1, 1)),
            &[(oid::EXTENDED_KEY_USAGE_OID, false, ev_eku(&[oid::EKU_OCSP_SIGNING_OID])), (oid::OCSP_NO_CHECK_OID, false, ev_null())],
            &root_sign,
        );
        let responder_cert: FixtureCert<'_> = asn1::parse_single(&responder_der).unwrap();
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &responder_subject_der,
            true,
            this_update,
            next_update,
            vec![responder_cert],
            CertIdHash::Sha1,
            &leaf_sign,
        );
        let cms =
            build_stapled_cms(&leaf_der, &root_der, &[&responder_der], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_responder_good", &cms);
    }

    // 4. Forged revocation: a Revoked OCSP with a correct CertID (real issuer name+key+serial)
    //    that claims to come from the root but is signed with the attacker's key. The signature
    //    is pinned to the trust-anchored issuer's key, so verification fails and it is ignored.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            false,
            this_update,
            None,
            vec![],
            CertIdHash::Sha1,
            &leaf_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_forged_revoked", &cms);
    }

    // 4b. CertID mismatch: a Revoked OCSP validly signed by the real root, but whose CertID
    //     issuer_key_hash is computed over the wrong key. It does not identify this leaf/issuer
    //     pair, so it is discarded at certID matching before the signature is ever checked.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &leaf_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            false,
            this_update,
            None,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_certid_mismatch_revoked", &cms);
    }

    // 5. Expired leaf with a Good staple -> the certificate is untrusted.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &expired_leaf_serial,
            &root_subject_der,
            true,
            this_update,
            None,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms =
            build_stapled_cms(&expired_leaf_der, &root_der, &[], &expired_leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("expired_leaf_good_staple", &cms);
    }

    // 6. Good staple whose nextUpdate is long past -> the stale response is ignored
    //    (not accepted as a current "good" signal); the leaf stays trusted with no revocation status.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            true,
            this_update,
            Some((2024, 1, 16)),
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_good_stale_response", &cms);
    }

    // 6b. Good staple with no nextUpdate and a thisUpdate well over 7 days old -> the relying-party
    //     freshness cap for nextUpdate-less responses expires it, so it is ignored (no status).
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            true,
            this_update,
            None,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_good_no_next_update", &cms);
    }

    // 7. Good OCSP signed by the issuing root, but with a SHA-256 CertID (RFC 6960 allows any
    //    hash). The staple must still be matched and recorded as good, not silently ignored.
    {
        let ocsp = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &leaf_serial,
            &root_subject_der,
            true,
            this_update,
            next_update,
            vec![],
            CertIdHash::Sha256,
            &root_sign,
        );
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("stapled_issuer_good_sha256_certid", &cms);
    }

    // 8. Three-level chain root -> intermediate -> leaf: the leaf staples Good (signed by the
    //    intermediate) but the intermediate staples Revoked (signed by the root). The revocation
    //    must be promoted over the leaf's own Good status and the error must name the intermediate.
    {
        let (intermediate_der, intermediate_serial, intermediate_subject_der) = build_cert(
            &root_subject_der,
            "Test Stapling Intermediate CA",
            &leaf_spki,
            validity_utc((2024, 1, 1), (2035, 1, 1)),
            &[(oid::BASIC_CONSTRAINTS_OID, true, ev_basic_constraints_ca()), (oid::KEY_USAGE_OID, true, ev_key_usage_ca())],
            &root_sign,
        );
        let (chain_leaf_der, chain_leaf_serial, _) = build_cert(
            &intermediate_subject_der,
            "Anu Allkirjastaja",
            &leaf_spki,
            validity_utc((2024, 1, 1), (2035, 1, 1)),
            &[(oid::EXTENDED_KEY_USAGE_OID, false, ev_eku(&[oid::EKU_EMAIL_PROTECTION_OID]))],
            &leaf_sign,
        );
        let leaf_good = build_ocsp_response(
            &intermediate_subject_der,
            &leaf_pubkey_bits,
            &chain_leaf_serial,
            &intermediate_subject_der,
            true,
            this_update,
            next_update,
            vec![],
            CertIdHash::Sha1,
            &leaf_sign,
        );
        let intermediate_revoked = build_ocsp_response(
            &root_subject_der,
            &root_pubkey_bits,
            &intermediate_serial,
            &root_subject_der,
            false,
            this_update,
            next_update,
            vec![],
            CertIdHash::Sha1,
            &root_sign,
        );
        let cms = build_stapled_cms(
            &chain_leaf_der,
            &root_der,
            &[&intermediate_der],
            &chain_leaf_serial,
            &intermediate_subject_der,
            &[&leaf_good, &intermediate_revoked],
            content,
            &leaf_sign,
        );
        write("stapled_intermediate_revoked", &cms);
    }

    // OpenSSL interop (independent oracle): same root/leaf, but the OCSP responses are produced by
    // `openssl ocsp` instead of build_ocsp_response, then embedded and validated by our code.
    {
        let dir = std::env::temp_dir().join("rust_smime_ocsp_interop");
        fs::create_dir_all(&dir).unwrap();
        let ca_pem = write_pem_cert(&dir, "root.pem", &root_der);
        let leaf_pem = write_pem_cert(&dir, "leaf.pem", &leaf_der);
        let leaf_not_after = "350101000000Z"; // leaf validity not_after, 2035-01-01

        // OpenSSL good/revoked OCSP signed directly by the issuing root.
        let ocsp =
            openssl_ocsp_response(&dir, &ca_pem, &leaf_pem, &leaf_serial, leaf_not_after, false, &ca_pem, "tests/keys/test_rsa_sign.key");
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("openssl_issuer_good", &cms);

        let ocsp =
            openssl_ocsp_response(&dir, &ca_pem, &leaf_pem, &leaf_serial, leaf_not_after, true, &ca_pem, "tests/keys/test_rsa_sign.key");
        let cms = build_stapled_cms(&leaf_der, &root_der, &[], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("openssl_issuer_revoked", &cms);

        // OpenSSL good OCSP signed by a delegated, authorized responder (EKU ocsp-signing + ocsp-nocheck).
        let (responder_der, _rs, _rsubj) = build_cert(
            &root_subject_der,
            "Test OCSP Responder",
            &leaf_spki,
            validity_utc((2024, 1, 1), (2035, 1, 1)),
            &[(oid::EXTENDED_KEY_USAGE_OID, false, ev_eku(&[oid::EKU_OCSP_SIGNING_OID])), (oid::OCSP_NO_CHECK_OID, false, ev_null())],
            &root_sign,
        );
        let responder_pem = write_pem_cert(&dir, "responder.pem", &responder_der);
        let ocsp =
            openssl_ocsp_response(&dir, &ca_pem, &leaf_pem, &leaf_serial, leaf_not_after, false, &responder_pem, "tests/keys/test_rsa.key");
        let cms =
            build_stapled_cms(&leaf_der, &root_der, &[&responder_der], &leaf_serial, &root_subject_der, &[&ocsp], content, &leaf_sign);
        write("openssl_responder_good", &cms);
    }
}
