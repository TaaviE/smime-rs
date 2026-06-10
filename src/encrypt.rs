//! S/MIME encryption: build CMS EnvelopedData (AES-256-CBC) and AuthEnvelopedData
//! (AES-256-GCM) for a set of recipient certificates. This mirrors the encryption
//! capability of the `@zone-eu/smime-js` Node library so it can be exposed over WASM.
//!
//! Recipient handling matches smime-js: RSA key transport via OAEP (SHA-256/MGF1-SHA256)
//! or PKCS#1 v1.5, and ECDH KARI (P-256/384/521) with X9.63-KDF(SHA-256) + AES-256 key wrap.
//! X25519 recipients use KARI per RFC 8418 with HKDF-SHA256 + AES-256 key wrap.

use crate::cryptography_x509::certificate::Certificate;
use crate::cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, Asn1ReadableOrWritable, EcParameters, GcmParameters, PSS_SHA256_HASH_ALG,
    PSS_SHA256_MASK_GEN_ALG, RsaOaepParameters,
};
use crate::cryptography_x509::oid;
use crate::cryptography_x509::pkcs7::*;
use crate::errors::SmimeError;

use aes_kw::KeyInit as _;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;

/// Content cipher selecting EnvelopedData vs AuthEnvelopedData, matching smime-js.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContentCipher {
    /// AES-256-CBC → EnvelopedData
    Aes256Cbc,
    /// AES-256-GCM → AuthEnvelopedData
    Aes256Gcm,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).unwrap();
    buf
}

/// AES-CBC content encryption with PKCS#7 padding (128/192/256-bit keys).
pub fn encrypt_aes_cbc(cek: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded_len = (plaintext.len() / 16 + 1) * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    match cek.len() {
        16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(cek, iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec(),
        24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(cek, iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec(),
        32 => cbc::Encryptor::<aes::Aes256>::new_from_slices(cek, iv)
            .unwrap()
            .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec(),
        _ => panic!("invalid AES key length: {}", cek.len()),
    }
}

/// AES-256-GCM content encryption (12-byte nonce, 16-byte tag). Returns (ciphertext, tag).
fn encrypt_aes256_gcm(cek: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    use aes_gcm::{KeyInit, aead::AeadInOut};
    let mut buf = plaintext.to_vec();
    let tag = aes_gcm::Aes256Gcm::new_from_slice(cek).unwrap().encrypt_inout_detached(nonce.into(), aad, (&mut buf[..]).into()).unwrap();
    (buf, tag.into())
}

/// Validate a recipient certificate's public key:
/// RSA 2048-4096 bits, EC P-256/384/521, or X25519.
pub fn validate_cert_key(cert_pem: &str) -> Result<(), SmimeError> {
    let der = pem::parse(cert_pem).map_err(|e| SmimeError::Raw(format!("invalid certificate PEM: {}", e)))?.into_contents();
    let cert: Certificate = asn1::parse_single(&der).map_err(|e| SmimeError::Raw(format!("invalid certificate: {}", e)))?;
    validate_spki(&cert)
}

fn validate_spki(cert: &Certificate) -> Result<(), SmimeError> {
    match &cert.tbs_cert.spki.algorithm.params {
        AlgorithmParameters::RSA(_) => {
            let spki_der = asn1::write_single(&cert.tbs_cert.spki).map_err(|e| SmimeError::Raw(format!("SPKI DER: {}", e)))?;
            let pk =
                rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| SmimeError::Raw(format!("invalid RSA public key: {}", e)))?;
            let bits = pk.n().bits();
            if !(2048..=4096).contains(&bits) {
                return Err(SmimeError::Raw(format!("unsupported RSA key size: {} bits (expected 2048-4096)", bits)));
            }
            Ok(())
        }
        AlgorithmParameters::ECDSA(Some(EcParameters::NamedCurve(curve))) => {
            if *curve == oid::EC_SECP256R1 || *curve == oid::EC_SECP384R1 || *curve == oid::EC_SECP521R1 {
                Ok(())
            } else {
                Err(SmimeError::Raw(format!("unsupported EC curve: {}", curve)))
            }
        }
        AlgorithmParameters::X25519 => Ok(()),
        other => Err(SmimeError::Raw(format!("unsupported recipient key type: {:?}", other))),
    }
}

/// Build a KeyTransRecipientInfo (RSA). `pkcs1v15` selects PKCS#1 v1.5, otherwise OAEP (SHA-256).
fn build_ktri(cek: &[u8], cert: &Certificate, pkcs1v15: bool) -> Result<Vec<u8>, SmimeError> {
    let spki_der = asn1::write_single(&cert.tbs_cert.spki).map_err(|e| SmimeError::Raw(format!("SPKI DER: {}", e)))?;
    let rsa_pub =
        rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| SmimeError::Raw(format!("invalid RSA public key: {}", e)))?;
    let mut rng = rsa::rand_core::UnwrapErr(getrandom::SysRng);

    let (encrypted_cek, kea_params) = if pkcs1v15 {
        let ct = rsa_pub.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, cek).map_err(|e| SmimeError::Raw(format!("RSA PKCS#1 v1.5: {}", e)))?;
        (ct, AlgorithmParameters::RSA(Some(())))
    } else {
        let ct =
            rsa_pub.encrypt(&mut rng, rsa::Oaep::<sha2::Sha256>::new(), cek).map_err(|e| SmimeError::Raw(format!("RSA-OAEP: {}", e)))?;
        let params =
            RsaOaepParameters { hash_algorithm: PSS_SHA256_HASH_ALG, mask_gen_algorithm: PSS_SHA256_MASK_GEN_ALG, p_source_func: None };
        (ct, AlgorithmParameters::RsaesOaep(Box::new(params)))
    };

    let ias = IssuerAndSerialNumber { issuer: cert.tbs_cert.issuer.clone(), serial_number: cert.tbs_cert.serial.clone() };
    let ktri = KeyTransRecipientInfo {
        version: 0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(ias),
        key_encryption_algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: kea_params },
        encrypted_key: &encrypted_cek,
    };
    asn1::write_single(&RecipientInfo::KeyTransRecipientInfo(ktri)).map_err(|e| SmimeError::Raw(format!("KTRI DER: {}", e)))
}

/// Build a KeyAgreeRecipientInfo (ECDH, NIST curves) using X9.63-KDF(SHA-256) and AES-256 key wrap.
fn build_kari(cek: &[u8], cert: &Certificate, curve: &asn1::ObjectIdentifier) -> Result<Vec<u8>, SmimeError> {
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    let recipient_pk_bytes = cert.tbs_cert.spki.subject_public_key.as_bytes();

    // ECC-CMS-SharedInfo (RFC 5753 §7.2): keyInfo = AES-256-WRAP, suppPubInfo = key length in bits.
    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Other(oid::AES256_WRAP, None) },
        entity_u_info: None,
        supp_pub_info: &256u32.to_be_bytes(),
    };
    let shared_info_der = asn1::write_single(&shared_info).map_err(|e| SmimeError::Raw(format!("SharedInfo DER: {}", e)))?;

    // keyEncryptionAlgorithm = dhSinglePass-stdDH-sha256kdf with AES-256-WRAP as parameter.
    let wrap_alg_der = asn1::write_single(&AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(oid::AES256_WRAP, None),
    })
    .map_err(|e| SmimeError::Raw(format!("wrap alg DER: {}", e)))?;
    let wrap_alg_tlv: asn1::Tlv = asn1::parse_single(&wrap_alg_der).map_err(|e| SmimeError::Raw(format!("wrap alg TLV: {}", e)))?;

    macro_rules! kari_for_curve {
        ($mod:ident) => {{
            let recipient_pk = $mod::PublicKey::from_sec1_bytes(recipient_pk_bytes)
                .map_err(|e| SmimeError::Raw(format!("invalid recipient EC point: {}", e)))?;
            let eph_sk = $mod::NonZeroScalar::generate();
            let eph_pk = $mod::PublicKey::from_secret_scalar(&eph_sk);
            let eph_pk_bytes = eph_pk.to_sec1_point(false);
            let z = $mod::ecdh::diffie_hellman(&eph_sk, recipient_pk.as_affine());

            let mut kek = vec![0u8; 32];
            ansi_x963_kdf::derive_key_into::<sha2::Sha256>(z.raw_secret_bytes(), &shared_info_der, &mut kek)
                .map_err(|_| SmimeError::Raw("X9.63-KDF output too long".into()))?;

            let mut wrapped_cek = vec![0u8; cek.len() + 8];
            aes_kw::KwAes256::new_from_slice(&kek)
                .unwrap()
                .wrap_key(cek, &mut wrapped_cek)
                .map_err(|e| SmimeError::Raw(format!("AES key wrap: {}", e)))?;

            (eph_pk_bytes.as_bytes().to_vec(), wrapped_cek)
        }};
    }

    let (eph_pk_bytes, wrapped_cek) = if *curve == oid::EC_SECP256R1 {
        kari_for_curve!(p256)
    } else if *curve == oid::EC_SECP384R1 {
        kari_for_curve!(p384)
    } else if *curve == oid::EC_SECP521R1 {
        kari_for_curve!(p521)
    } else {
        return Err(SmimeError::Raw(format!("unsupported EC curve: {}", curve)));
    };

    let ias = IssuerAndSerialNumber { issuer: cert.tbs_cert.issuer.clone(), serial_number: cert.tbs_cert.serial.clone() };
    let rek = RecipientEncryptedKey { rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias), encrypted_key: &wrapped_cek };
    let reks = [rek];
    let originator_key = OriginatorPublicKey {
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::ECDSA(Some(EcParameters::NamedCurve(curve.clone()))),
        },
        public_key: asn1::BitString::new(&eph_pk_bytes, 0).unwrap(),
    };
    let kari = KeyAgreeRecipientInfo {
        version: 3,
        originator: OriginatorIdentifierOrKey::OriginatorKey(originator_key),
        ukm: None,
        key_encryption_algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Other(oid::DH_STD_SHA256, Some(wrap_alg_tlv)),
        },
        recipient_encrypted_keys: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&reks)),
    };
    asn1::write_single(&RecipientInfo::KeyAgreeRecipientInfo(kari)).map_err(|e| SmimeError::Raw(format!("KARI DER: {}", e)))
}

/// Build a KeyAgreeRecipientInfo for an X25519 recipient (RFC 8418)
fn build_kari_x25519(cek: &[u8], cert: &Certificate) -> Result<Vec<u8>, SmimeError> {
    let recipient_pk_bytes: [u8; 32] = cert
        .tbs_cert
        .spki
        .subject_public_key
        .as_bytes()
        .try_into()
        .map_err(|_| SmimeError::Raw("X25519 public key must be 32 bytes".into()))?;

    let eph_sk = x25519_dalek::StaticSecret::from(random_bytes::<32>());
    let eph_pk = x25519_dalek::PublicKey::from(&eph_sk);
    let shared = eph_sk.diffie_hellman(&x25519_dalek::PublicKey::from(recipient_pk_bytes));
    // RFC 7748 §6 / RFC 8418 §2: reject an all-zero shared secret (low-order recipient key).
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    if shared.as_bytes().ct_eq(&[0u8; 32]).into() {
        return Err(SmimeError::Raw("X25519 shared secret is all-zero".into()));
    }

    // ECC-CMS-SharedInfo (RFC 8418 §2): keyInfo = AES-256-WRAP, suppPubInfo = KEK length in bits.
    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Other(oid::AES256_WRAP, None) },
        entity_u_info: None,
        supp_pub_info: &256u32.to_be_bytes(),
    };
    let shared_info_der = asn1::write_single(&shared_info).map_err(|e| SmimeError::Raw(format!("SharedInfo DER: {}", e)))?;

    // RFC 8418 §2.2: no ukm → no salt; KEK = HKDF-Expand(HKDF-Extract(no salt, Z), SharedInfo, 32).
    let mut kek = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes())
        .expand(&shared_info_der, &mut kek)
        .map_err(|e| SmimeError::Raw(format!("HKDF expand: {}", e)))?;

    let mut wrapped_cek = vec![0u8; cek.len() + 8];
    aes_kw::KwAes256::new_from_slice(&kek)
        .unwrap()
        .wrap_key(cek, &mut wrapped_cek)
        .map_err(|e| SmimeError::Raw(format!("AES key wrap: {}", e)))?;

    // keyEncryptionAlgorithm = dhSinglePass-stdDH-hkdf-sha256-scheme with AES-256-WRAP as parameter.
    let wrap_alg_der = asn1::write_single(&AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(oid::AES256_WRAP, None),
    })
    .map_err(|e| SmimeError::Raw(format!("wrap alg DER: {}", e)))?;
    let wrap_alg_tlv: asn1::Tlv = asn1::parse_single(&wrap_alg_der).map_err(|e| SmimeError::Raw(format!("wrap alg TLV: {}", e)))?;

    let ias = IssuerAndSerialNumber { issuer: cert.tbs_cert.issuer.clone(), serial_number: cert.tbs_cert.serial.clone() };
    let rek = RecipientEncryptedKey { rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias), encrypted_key: &wrapped_cek };
    let reks = [rek];
    // RFC 8418 §3.2: originatorKey algorithm MUST be id-X25519, public key is the raw 32 bytes.
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
            params: AlgorithmParameters::Other(oid::DH_HKDF_SHA256, Some(wrap_alg_tlv)),
        },
        recipient_encrypted_keys: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&reks)),
    };
    asn1::write_single(&RecipientInfo::KeyAgreeRecipientInfo(kari)).map_err(|e| SmimeError::Raw(format!("KARI DER: {}", e)))
}

/// Build a RecipientInfo for one certificate.
/// An unsupported key type or size is anerror: silently dropping a recipient would produce
/// messages that some recipients cannot read without any indication to the sender.
fn build_recipient_info(cek: &[u8], cert: &Certificate, pkcs1v15: bool) -> Result<Vec<u8>, SmimeError> {
    validate_spki(cert)?;
    match &cert.tbs_cert.spki.algorithm.params {
        AlgorithmParameters::RSA(_) => build_ktri(cek, cert, pkcs1v15),
        AlgorithmParameters::ECDSA(Some(EcParameters::NamedCurve(curve))) => build_kari(cek, cert, curve),
        AlgorithmParameters::X25519 => build_kari_x25519(cek, cert),
        _ => unreachable!("validate_spki accepted an unsupported key type"),
    }
}

/// Encrypt `plaintext` to the given recipient certificates (PEM).
/// An empty `certs_pem` or any certificate with an unsupported key returns an error.
/// Returns the DER-encoded CMS ContentInfo.
/// `pkcs1v15` selects RSA PKCS#1 v1.5 over OAEP.
pub fn encrypt(certs_pem: &[String], plaintext: &[u8], cipher: ContentCipher, pkcs1v15: bool) -> Result<Vec<u8>, SmimeError> {
    if certs_pem.is_empty() {
        return Err(SmimeError::Raw("no recipient certificates provided".into()));
    }

    let cek: [u8; 32] = random_bytes();

    // Parse certs first so their DER backs the borrowed issuer/serial in each RecipientInfo.
    let mut cert_ders: Vec<Vec<u8>> = Vec::new();
    for pem_str in certs_pem {
        let der = pem::parse(pem_str).map_err(|e| SmimeError::Raw(format!("invalid certificate PEM: {}", e)))?.into_contents();
        cert_ders.push(der);
    }

    let mut ris_der: Vec<Vec<u8>> = Vec::new();
    for der in &cert_ders {
        let cert: Certificate = asn1::parse_single(der).map_err(|e| SmimeError::Raw(format!("invalid certificate: {}", e)))?;
        ris_der.push(build_recipient_info(&cek, &cert, pkcs1v15)?);
    }

    let ris: Vec<RecipientInfo> = ris_der.iter().map(|d| asn1::parse_single(d).unwrap()).collect();
    let all_ktri = ris.iter().all(|ri| matches!(ri, RecipientInfo::KeyTransRecipientInfo(_)));

    let der = match cipher {
        ContentCipher::Aes256Cbc => {
            let iv: [u8; 16] = random_bytes();
            let ciphertext = encrypt_aes_cbc(&cek, &iv, plaintext);
            let enveloped = EnvelopedData {
                version: if all_ktri { 0 } else { 2 },
                originator_info: None,
                recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&ris)),
                encrypted_content_info: EncryptedContentInfo {
                    content_type: PKCS7_DATA_OID,
                    content_encryption_algorithm: AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: AlgorithmParameters::Aes256Cbc(iv),
                    },
                    encrypted_content: Some(&ciphertext),
                },
                unprotected_attrs: None,
            };
            let content_info = ContentInfo {
                content_type: asn1::DefinedByMarker::marker(),
                content: Content::EnvelopedData(asn1::Explicit::new(Box::new(enveloped))),
            };
            asn1::write_single(&content_info).map_err(|e| SmimeError::Raw(format!("EnvelopedData DER: {}", e)))?
        }
        ContentCipher::Aes256Gcm => {
            let nonce: [u8; 12] = random_bytes();
            let (ciphertext, tag) = encrypt_aes256_gcm(&cek, &nonce, &[], plaintext);
            let auth_enveloped = AuthEnvelopedData {
                version: 0,
                originator_info: None,
                recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&ris)),
                auth_encrypted_content_info: EncryptedContentInfo {
                    content_type: PKCS7_DATA_OID,
                    content_encryption_algorithm: AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: AlgorithmParameters::Aes256Gcm(GcmParameters { nonce: &nonce, icv_len: 16 }),
                    },
                    encrypted_content: Some(&ciphertext),
                },
                auth_attrs: None,
                mac: &tag,
                unauth_attrs: None,
            };
            let content_info = ContentInfo {
                content_type: asn1::DefinedByMarker::marker(),
                content: Content::AuthEnvelopedData(asn1::Explicit::new(Box::new(auth_enveloped))),
            };
            asn1::write_single(&content_info).map_err(|e| SmimeError::Raw(format!("AuthEnvelopedData DER: {}", e)))?
        }
    };

    Ok(der)
}
