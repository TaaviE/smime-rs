use crate::cryptography_x509::common;
use crate::cryptography_x509::csr::Attributes;
use crate::cryptography_x509::oid::MESSAGE_DIGEST_OID;
use crate::cryptography_x509_verify::error::CryptographyError;
use crate::cryptography_x509_verify::sign::{
    HashType, SignatureParameters, hash_oid_to_hash_type, verify_signature_with_signature_algorithm,
};
use crate::errors::SmimeError;
use crate::types::AnyPublicKey;
use p256::elliptic_curve::subtle::ConstantTimeEq;
use sha2::Digest;

/// Verifies the digest stored in signed attributes matches that of content.
pub fn verify_message_digest(
    digest_algorithm: &common::AlgorithmIdentifier<'_>,
    authenticated_attributes: Option<&Attributes<'_>>,
    content: &[u8],
) -> Result<(), SmimeError> {
    let attrs = authenticated_attributes.ok_or(SmimeError::DigestVerify { err: "message-digest attribute missing".to_string() })?;

    let hash_type = hash_oid_to_hash_type(digest_algorithm.oid().clone())
        .map_err(|_| SmimeError::UnsupportedDigestAlg { alg: format!("{:?}", digest_algorithm.oid()), idx: 0 })?;

    let computed_digest =
        compute_hash(&hash_type, content).map_err(|_| SmimeError::DisallowedDigestAlg { alg: format!("{:?}", hash_type), idx: 0 })?;

    for attr in attrs.unwrap_read().clone() {
        let mut values: Vec<_> = match attr.type_id {
            MESSAGE_DIGEST_OID => attr.values.unwrap_read().clone().collect(),
            _ => continue,
        };
        let expected_digest = match values.as_mut_slice() {
            [single] => asn1::parse_single::<&[u8]>(single.full_data())
                .map_err(|e| SmimeError::DigestVerify { err: format!("malformed message-digest value: {}", e) })?,
            _ => {
                return Err(SmimeError::DigestVerify {
                    err: format!("message-digest attribute must have exactly one value, found {}", values.len()),
                });
            }
        };
        return match expected_digest.ct_eq(computed_digest.as_slice()).into() {
            true => Ok(()),
            false => Err(SmimeError::DigestVerify {
                err: format!(
                    "digests not equivalent: expected {}, computed {}",
                    hex::encode(expected_digest),
                    hex::encode(&computed_digest)
                ),
            }),
        };
    }

    Err(SmimeError::DigestVerify { err: "message-digest attribute missing".to_string() })
}

fn extract_subject_public_key(spki_der: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let spki: common::SubjectPublicKeyInfo<'_> =
        asn1::parse_single(spki_der).map_err(|e| CryptographyError::from(format!("Failed to parse SubjectPublicKeyInfo: {e}")))?;
    Ok(spki.subject_public_key.as_bytes().to_vec())
}

fn compute_hash(hash: &HashType, data: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    match hash {
        HashType::SHA256 => Ok(<sha2::Sha256 as Digest>::digest(data).to_vec()),
        HashType::SHA384 => Ok(<sha2::Sha384 as Digest>::digest(data).to_vec()),
        HashType::SHA512 => Ok(<sha2::Sha512 as Digest>::digest(data).to_vec()),
        HashType::SHA3_256 => Ok(libcrux_sha3::sha256(data).to_vec()),
        HashType::SHA3_384 => Ok(libcrux_sha3::sha384(data).to_vec()),
        HashType::SHA3_512 => Ok(libcrux_sha3::sha512(data).to_vec()),
        HashType::SHAKE128 => Ok(libcrux_sha3::shake128::<32>(data).to_vec()),
        HashType::SHAKE256 => Ok(libcrux_sha3::shake256::<64>(data).to_vec()),
        _ => Err(CryptographyError::from(format!("Unsupported hash algorithm: {hash:?}"))),
    }
}

/// If hash is allowed with the signature scheme or if it is too weak (but possibly supported elsewhere)
fn check_hash_allowed(params: &SignatureParameters) -> Result<(), CryptographyError> {
    use HashType::*;
    let (hash, label) = match params {
        SignatureParameters::RSAPKCS1v15 { hash } => (hash, "RSA PKCS#1 v1.5"),
        SignatureParameters::RSAPSS { hash } => (hash, "RSA-PSS"),
        SignatureParameters::ECDSA { hash } => (hash, "ECDSA"),
        _ => return Ok(()),
    };
    if ![SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512].contains(hash) {
        return Err(CryptographyError::from(format!("Unsupported {label} hash algorithm: {hash:?}")));
    }
    Ok(())
}

/// Reject hash algorithms that are too weak for the key size
pub fn check_hash_recommended(key: &AnyPublicKey, params: &SignatureParameters) -> Result<(), CryptographyError> {
    let (hash, recommended, label) = match (key, params) {
        (AnyPublicKey::P256 { .. }, SignatureParameters::ECDSA { hash }) => (
            hash,
            &[HashType::SHA256, HashType::SHA3_256, HashType::SHA384, HashType::SHA3_384, HashType::SHA512, HashType::SHA3_512][..],
            "ECDSA P-256",
        ),
        (AnyPublicKey::P384 { .. }, SignatureParameters::ECDSA { hash }) => {
            (hash, &[HashType::SHA384, HashType::SHA3_384, HashType::SHA512, HashType::SHA3_512][..], "ECDSA P-384")
        }
        (AnyPublicKey::P521 { .. }, SignatureParameters::ECDSA { hash }) => {
            (hash, &[HashType::SHA512, HashType::SHA3_512][..], "ECDSA P-521")
        }
        _ => return Ok(()),
    };
    if !recommended.contains(hash) {
        return Err(CryptographyError::from(format!("{label}: hash {hash:?} is too weak for this key size")));
    }
    Ok(())
}

macro_rules! rsa_verify_fn {
    ($name:ident, $scheme:ident, $label:expr) => {
        fn $name(spki_der: &[u8], hash: &HashType, data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
            use rsa::pkcs8::DecodePublicKey;
            use signature::hazmat::PrehashVerifier;
            let pub_key = rsa::RsaPublicKey::from_public_key_der(spki_der)
                .map_err(|e| CryptographyError::from(format!("Failed to parse RSA public key: {e}")))?;
            let sig = rsa::$scheme::Signature::try_from(signature)
                .map_err(|e| CryptographyError::from(format!(concat!("Invalid ", $label, " signature: {}"), e)))?;
            let prehash = compute_hash(hash, data)?;
            match hash {
                HashType::SHA256 => rsa::$scheme::VerifyingKey::<sha2::Sha256>::new(pub_key).verify_prehash(&prehash, &sig),
                HashType::SHA384 => rsa::$scheme::VerifyingKey::<sha2::Sha384>::new(pub_key).verify_prehash(&prehash, &sig),
                HashType::SHA512 => rsa::$scheme::VerifyingKey::<sha2::Sha512>::new(pub_key).verify_prehash(&prehash, &sig),
                HashType::SHA3_256 => rsa::$scheme::VerifyingKey::<sha3::Sha3_256>::new(pub_key).verify_prehash(&prehash, &sig),
                HashType::SHA3_384 => rsa::$scheme::VerifyingKey::<sha3::Sha3_384>::new(pub_key).verify_prehash(&prehash, &sig),
                HashType::SHA3_512 => rsa::$scheme::VerifyingKey::<sha3::Sha3_512>::new(pub_key).verify_prehash(&prehash, &sig),
                _ => unreachable!(),
            }
            .map_err(|e| CryptographyError::from(format!("Signature verification failed: {e}")))?;
            Ok(())
        }
    };
}

rsa_verify_fn!(verify_rsa_pkcs1v15, pkcs1v15, "PKCS1v15");
rsa_verify_fn!(verify_rsa_pss, pss, "PSS");

fn verify_p256(spki_der: &[u8], hash: &HashType, data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    use rsa::pkcs8::DecodePublicKey;
    use signature::hazmat::PrehashVerifier;
    let prehash = compute_hash(hash, data)?;
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| CryptographyError::from(format!("Invalid P-256 public key: {e}")))?;
    let sig = p256::ecdsa::Signature::from_der(signature).map_err(|e| CryptographyError::from(format!("Invalid ECDSA signature: {e}")))?;
    vk.verify_prehash(&prehash, &sig).map_err(|e| CryptographyError::from(format!("Signature verification failed: {e}")))?;
    Ok(())
}

fn verify_p384(spki_der: &[u8], hash: &HashType, data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    use rsa::pkcs8::DecodePublicKey;
    use signature::hazmat::PrehashVerifier;
    let prehash = compute_hash(hash, data)?;
    let vk = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| CryptographyError::from(format!("Invalid P-384 public key: {e}")))?;
    let sig = p384::ecdsa::Signature::from_der(signature).map_err(|e| CryptographyError::from(format!("Invalid ECDSA signature: {e}")))?;
    vk.verify_prehash(&prehash, &sig).map_err(|e| CryptographyError::from(format!("Signature verification failed: {e}")))?;
    Ok(())
}

fn verify_p521(spki_der: &[u8], hash: &HashType, data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    use rsa::pkcs8::DecodePublicKey;
    use signature::hazmat::PrehashVerifier;
    let prehash = compute_hash(hash, data)?;
    let vk = p521::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| CryptographyError::from(format!("Invalid P-521 public key: {e}")))?;
    let sig = p521::ecdsa::Signature::from_der(signature).map_err(|e| CryptographyError::from(format!("Invalid ECDSA signature: {e}")))?;
    vk.verify_prehash(&prehash, &sig).map_err(|e| CryptographyError::from(format!("Signature verification failed: {e}")))?;
    Ok(())
}

fn verify_ed25519(spki_der: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    use rsa::pkcs8::DecodePublicKey;
    use signature::Verifier;
    let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| CryptographyError::from(format!("Invalid Ed25519 public key: {e}")))?;
    let sig =
        ed25519_dalek::Signature::from_slice(signature).map_err(|e| CryptographyError::from(format!("Invalid Ed25519 signature: {e}")))?;
    vk.verify(data, &sig).map_err(|e| CryptographyError::from(format!("Signature verification failed: {e}")))?;
    Ok(())
}

fn verify_mldsa44(spki_der: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    let key_bytes = extract_subject_public_key(spki_der)?;
    let vk_array: [u8; 1312] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-44 verification key must be 1312 bytes, got {}", key_bytes.len())))?;
    let sig_array: [u8; 2420] = signature
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-44 signature must be 2420 bytes, got {}", signature.len())))?;
    let vk = libcrux_ml_dsa::ml_dsa_44::MLDSA44VerificationKey::new(vk_array);
    let sig = libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature::new(sig_array);
    crate::cryptography_x509_verify::mldsa::verify_mldsa44(&vk, data, &sig).map_err(CryptographyError::from)?;
    Ok(())
}

fn verify_mldsa65(spki_der: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    let key_bytes = extract_subject_public_key(spki_der)?;
    let vk_array: [u8; 1952] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-65 verification key must be 1952 bytes, got {}", key_bytes.len())))?;
    let sig_array: [u8; 3309] = signature
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-65 signature must be 3309 bytes, got {}", signature.len())))?;
    let vk = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey::new(vk_array);
    let sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(sig_array);
    crate::cryptography_x509_verify::mldsa::verify_mldsa65(&vk, data, &sig).map_err(CryptographyError::from)?;
    Ok(())
}

fn verify_mldsa87(spki_der: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptographyError> {
    let key_bytes = extract_subject_public_key(spki_der)?;
    let vk_array: [u8; 2592] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-87 verification key must be 2592 bytes, got {}", key_bytes.len())))?;
    let sig_array: [u8; 4627] = signature
        .try_into()
        .map_err(|_| CryptographyError::from(format!("ML-DSA-87 signature must be 4627 bytes, got {}", signature.len())))?;
    let vk = libcrux_ml_dsa::ml_dsa_87::MLDSA87VerificationKey::new(vk_array);
    let sig = libcrux_ml_dsa::ml_dsa_87::MLDSA87Signature::new(sig_array);
    crate::cryptography_x509_verify::mldsa::verify_mldsa87(&vk, data, &sig).map_err(CryptographyError::from)?;
    Ok(())
}

pub fn verify_signature(
    issuer_public_key: &AnyPublicKey,
    params: &SignatureParameters,
    signature: &[u8],
    data: &[u8],
) -> Result<(), CryptographyError> {
    check_hash_allowed(params)?;
    check_hash_recommended(issuer_public_key, params)?;
    match (issuer_public_key, params) {
        (AnyPublicKey::RSA { spki_der, .. }, SignatureParameters::RSAPKCS1v15 { hash }) => {
            verify_rsa_pkcs1v15(spki_der, hash, data, signature)
        }
        (AnyPublicKey::RSA { spki_der, .. }, SignatureParameters::RSAPSS { hash }) => verify_rsa_pss(spki_der, hash, data, signature),
        (AnyPublicKey::P256 { spki_der, .. }, SignatureParameters::ECDSA { hash }) => verify_p256(spki_der, hash, data, signature),
        (AnyPublicKey::P384 { spki_der, .. }, SignatureParameters::ECDSA { hash }) => verify_p384(spki_der, hash, data, signature),
        (AnyPublicKey::P521 { spki_der, .. }, SignatureParameters::ECDSA { hash }) => verify_p521(spki_der, hash, data, signature),
        (AnyPublicKey::Ed25519 { spki_der, .. }, _) => verify_ed25519(spki_der, data, signature),
        (AnyPublicKey::MLDSA44 { spki_der, .. }, _) => verify_mldsa44(spki_der, data, signature),
        (AnyPublicKey::MLDSA65 { spki_der, .. }, _) => verify_mldsa65(spki_der, data, signature),
        (AnyPublicKey::MLDSA87 { spki_der, .. }, _) => verify_mldsa87(spki_der, data, signature),
        _ => Err(CryptographyError::from("Unsupported key type or signature parameters".to_string())),
    }
}

fn encode_signed_attrs(attrs: &Attributes<'_>) -> Result<Vec<u8>, SmimeError> {
    let attr_vec = attrs.unwrap_read().clone().collect::<Vec<_>>();
    let mut encoded_attrs = attr_vec
        .into_iter()
        .map(|attr| {
            let der =
                asn1::write_single(&attr).map_err(|e| SmimeError::SigVerify { err: format!("failed to encode signed attribute: {e}") })?;
            Ok((der, attr))
        })
        .collect::<Result<Vec<_>, SmimeError>>()?;

    encoded_attrs.sort_by(|(der_a, _), (der_b, _)| der_a.cmp(der_b));

    let sorted_attrs = encoded_attrs.into_iter().map(|(_, attr)| attr).collect::<Vec<_>>();
    let writer = asn1::SetOfWriter::new(sorted_attrs);
    asn1::write_single(&writer).map_err(|e| SmimeError::SigVerify { err: format!("failed to encode signed attributes SET OF: {e}") })
}

fn do_verify_signature(
    public_key: &AnyPublicKey,
    digest_algorithm: &common::AlgorithmIdentifier<'_>,
    signature_algorithm: &common::AlgorithmIdentifier<'_>,
    signature_value: &[u8],
    data: &[u8],
) -> Result<(), SmimeError> {
    let hash_type = crate::hash_oid_to_hash_type_permitted(digest_algorithm.oid())?;
    let res = if *signature_algorithm.oid() == crate::cryptography_x509::oid::RSA_OID {
        let params = SignatureParameters::RSAPKCS1v15 { hash: hash_type };
        verify_signature(public_key, &params, signature_value, data)
    } else {
        verify_signature_with_signature_algorithm(public_key, signature_algorithm, signature_value, data)
            .map_err(|e| CryptographyError::from(e.to_string()))
    };
    res.map_err(|e| SmimeError::SigVerify { err: e.to_string() })
}

/// Verifies a detached signature where signedAttrs MUST be present.
/// The signature covers the DER-encoded SET OF signed attributes.
pub fn verify_detached_signature(
    public_key: &AnyPublicKey,
    digest_algorithm: &common::AlgorithmIdentifier<'_>,
    signature_algorithm: &common::AlgorithmIdentifier<'_>,
    authenticated_attributes: &Attributes<'_>,
    signature_value: &[u8],
) -> Result<(), SmimeError> {
    let data = encode_signed_attrs(authenticated_attributes)?;
    do_verify_signature(public_key, digest_algorithm, signature_algorithm, signature_value, &data)
}

/// Verifies a signature over eContent.
/// When signedAttrs is present the signature covers the DER-encoded SET OF
/// signed attributes; when absent it covers the raw eContent (RFC 5652 §5.4).
pub fn verify_econtent_signature(
    public_key: &AnyPublicKey,
    digest_algorithm: &common::AlgorithmIdentifier<'_>,
    signature_algorithm: &common::AlgorithmIdentifier<'_>,
    authenticated_attributes: Option<&Attributes<'_>>,
    signature_value: &[u8],
    e_content: &[u8],
) -> Result<(), SmimeError> {
    let data = match authenticated_attributes {
        Some(attrs) => encode_signed_attrs(attrs)?,
        None => e_content.to_vec(),
    };
    do_verify_signature(public_key, digest_algorithm, signature_algorithm, signature_value, &data)
}
