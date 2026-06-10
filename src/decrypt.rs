use crate::cryptography_x509::common::AlgorithmParameters;
use crate::cryptography_x509::oid::SUBJECT_KEY_IDENTIFIER_OID;
use crate::cryptography_x509::pkcs7::{
    AuthEnvelopedData, EnvelopedData, IssuerAndSerialNumber, KeyAgreeRecipientInfo, KeyTransRecipientInfo, OriginatorIdentifierOrKey,
    PKCS7_DATA_OID, RecipientInfo,
};
use crate::errors::SmimeError;

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey};

/// Key material for CMS decryption. All fields are optional - only the
/// ones relevant to the RecipientInfo types in the message are needed.
#[derive(Default)]
pub struct DecryptionKeys<'a> {
    /// PKCS#8 DER-encoded private key for KTRI (RSA) or KARI (ECDH/X25519)
    pub private_key_der: &'a [u8],
    /// DER-encoded recipient certificate for recipient matching
    pub recipient_cert_der: &'a [u8],
    /// Password for PasswordRecipientInfo (RFC 3211)
    pub password: Option<&'a str>,
    /// Pre-shared symmetric key for KEKRecipientInfo (RFC 5652 §6.2.3)
    pub kek: Option<&'a [u8]>,
}

/// RFC 9709: if the content encryption algorithm is id-alg-cek-hkdf-sha256,
/// unwrap to get the real algorithm and return the inner AlgorithmIdentifier DER
/// for CEK derivation. Otherwise return the algorithm as-is.
fn resolve_cek_hkdf<'a>(outer_cea: &'a AlgorithmParameters<'a>) -> Result<(AlgorithmParameters<'a>, Option<Vec<u8>>), SmimeError> {
    if let AlgorithmParameters::CekHkdfSha256(tlv) = outer_cea {
        let inner_der = tlv.full_data().to_vec();
        let inner = asn1::parse_single::<crate::cryptography_x509::common::AlgorithmIdentifier>(tlv.full_data())
            .map_err(|e| SmimeError::DecryptionFailed { err: format!("CEK-HKDF-SHA256 inner AlgorithmIdentifier: {}", e) })?;
        Ok((inner.params, Some(inner_der)))
    } else {
        Ok((outer_cea.clone(), None))
    }
}

/// Decrypt a CMS EnvelopedData structure. Returns the plaintext bytes,
/// or None if there is no encrypted content.
///
/// Only matching recipients are tried.
///
/// RFC 5652 §6, RFC 3565 (AES-CBC)
/// RFC 3370 §4.2.1 (RSAES-PKCS1-v1_5)
/// RFC 3560 (RSAES-OAEP).
pub fn decrypt_enveloped_data(
    enveloped_data: &EnvelopedData,
    keys: &DecryptionKeys,
) -> Result<(Option<Vec<u8>>, Vec<SmimeError>), SmimeError> {
    let mut warnings = Vec::new();
    let ciphertext = match enveloped_data.encrypted_content_info.encrypted_content {
        Some(ct) => ct,
        None => return Ok((None, warnings)),
    };

    // RFC 8551 §2.4.1: EnvelopedData contentType MUST be id-data for S/MIME
    if enveloped_data.encrypted_content_info.content_type != PKCS7_DATA_OID {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("unexpected contentType: {}", enveloped_data.encrypted_content_info.content_type),
        });
    }

    let outer_cea = &enveloped_data.encrypted_content_info.content_encryption_algorithm.params;
    let (cea, inner_alg_der) = resolve_cek_hkdf(outer_cea)?;

    let expected_key_len: usize = match &cea {
        AlgorithmParameters::Aes128Cbc(_) => 16,
        AlgorithmParameters::Aes192Cbc(_) => 24,
        AlgorithmParameters::Aes256Cbc(_) => 32,
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(_) => {
            warnings.push(SmimeError::WeakContentEncryptionAlg { alg: "3DES-CBC".into() });
            24
        }
        other => return Err(SmimeError::UnsupportedContentEncryptionAlg { alg: format!("{:?}", other) }),
    };

    let (cek, cek_warnings) = recover_cek(keys, &enveloped_data.recipient_infos, expected_key_len)?;
    warnings.extend(cek_warnings);

    let key = if let Some(ref der) = inner_alg_der { cms_cek_hkdf_sha256(&cek, der)? } else { cek };

    let plaintext = match &cea {
        AlgorithmParameters::Aes128Cbc(iv) => decrypt_cbc::<Aes128>(&key, iv, ciphertext),
        AlgorithmParameters::Aes192Cbc(iv) => decrypt_cbc::<Aes192>(&key, iv, ciphertext),
        AlgorithmParameters::Aes256Cbc(iv) => decrypt_cbc::<Aes256>(&key, iv, ciphertext),
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(iv) => decrypt_cbc::<des::TdesEde3>(&key, iv, ciphertext),
        _ => unreachable!(),
    }?;
    Ok((Some(plaintext), warnings))
}

/// Try each RecipientInfo until one succeeds, then validate CEK length (RFC 5652 §6.1).
fn recover_cek<'a>(
    keys: &DecryptionKeys,
    recipient_infos: &crate::cryptography_x509::common::Asn1ReadableOrWritable<
        asn1::SetOf<'a, RecipientInfo<'a>>,
        asn1::SetOfWriter<'a, RecipientInfo<'a>>,
    >,
    expected_key_len: usize,
) -> Result<(Vec<u8>, Vec<SmimeError>), SmimeError> {
    let cert = if !keys.recipient_cert_der.is_empty() {
        Some(
            asn1::parse_single::<crate::cryptography_x509::certificate::Certificate<'_>>(keys.recipient_cert_der)
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("recipient certificate: {}", e) })?,
        )
    } else {
        None
    };

    let mut warnings = Vec::new();
    let mut last_err = None;
    let mut cek = None;
    for ri in recipient_infos.unwrap_read().clone() {
        let needs_cert = matches!(ri, RecipientInfo::KeyTransRecipientInfo(_) | RecipientInfo::KeyAgreeRecipientInfo(_));
        let c = if needs_cert {
            match cert.as_ref() {
                Some(c) => Some(c),
                None => continue,
            }
        } else {
            None
        };
        let result = match ri {
            RecipientInfo::KeyTransRecipientInfo(ktri) => {
                if !ktri_matches_cert(&ktri, c.unwrap()) {
                    continue;
                }
                decrypt_ktri_cek(keys.private_key_der, &ktri)
            }
            RecipientInfo::KeyAgreeRecipientInfo(kari) => decrypt_kari_cek(keys.private_key_der, &kari, c.unwrap()),
            RecipientInfo::PasswordRecipientInfo(pwri) => decrypt_pwri_cek(keys.password, &pwri),
            RecipientInfo::KEKRecipientInfo(kekri) => decrypt_kekri_cek(keys.kek, &kekri),
            _ => continue,
        };
        match result {
            Ok((key, w)) => {
                warnings.extend(w);
                cek = Some(key);
                break;
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    let cek = match cek {
        Some(k) => k,
        None => return Err(last_err.unwrap_or(SmimeError::NoMatchingRecipient)),
    };

    if cek.len() != expected_key_len {
        return Err(SmimeError::DecryptionFailed {
            err: format!("CEK length {} does not match algorithm (expected {})", cek.len(), expected_key_len),
        });
    }
    Ok((cek, warnings))
}

/// Check whether a KTRI's RecipientIdentifier matches the given certificate.
fn ktri_matches_cert(ktri: &KeyTransRecipientInfo, cert: &crate::cryptography_x509::certificate::Certificate) -> bool {
    use crate::cryptography_x509::pkcs7::RecipientIdentifier;
    match &ktri.rid {
        RecipientIdentifier::IssuerAndSerialNumber(ias) => ias_matches_cert(ias, cert),
        RecipientIdentifier::SubjectKeyIdentifier(ski) => ski_matches_cert(ski, cert),
    }
}

/// Check whether an IssuerAndSerialNumber matches the given certificate.
fn ias_matches_cert(ias: &IssuerAndSerialNumber, cert: &crate::cryptography_x509::certificate::Certificate) -> bool {
    cert.issuer() == ias.issuer.unwrap_read() && cert.tbs_cert.serial == ias.serial_number
}

/// Check whether a SubjectKeyIdentifier matches the given certificate's SKI extension.
fn ski_matches_cert(ski: &[u8], cert: &crate::cryptography_x509::certificate::Certificate) -> bool {
    if let Ok(extensions) = cert.extensions() {
        if let Some(ext) = extensions.get_extension(&SUBJECT_KEY_IDENTIFIER_OID) {
            if let Ok(cert_ski) = ext.value::<&[u8]>() {
                return cert_ski == ski;
            }
        }
    }
    false
}

/// Decrypt the CEK via RSA key transport (KTRI).
/// Per RFC 3370 §4.2.1 (RSAES-PKCS#1-v1.5) and RFC 3560 (RSAES-OAEP).
fn decrypt_ktri_cek(private_key_der: &[u8], recipient_info: &KeyTransRecipientInfo) -> Result<(Vec<u8>, Vec<SmimeError>), SmimeError> {
    let mut warnings = Vec::new();
    let private_key =
        RsaPrivateKey::from_pkcs8_der(private_key_der).map_err(|e| SmimeError::PrivateKeyParseFailed { err: e.to_string() })?;
    let encrypted_key = recipient_info.encrypted_key;

    let cek = match &recipient_info.key_encryption_algorithm.params {
        // Padding errors are reported as-is: there is no realistic padding oracle here, as S/MIME
        // decryption failures are communicated to the user, not back to an attacker.
        AlgorithmParameters::RSA(_) => private_key
            .decrypt(Pkcs1v15Encrypt, encrypted_key)
            .map_err(|e| SmimeError::DecryptionFailed { err: format!("RSAES-PKCS1-v1_5 key decryption: {}", e) }),
        AlgorithmParameters::RsaesOaep(oaep_params) => {
            if let Some(ref p_source) = oaep_params.p_source_func {
                // RFC 3560 §3: only id-pSpecified with empty OCTET STRING (the default) is supported.
                let p_specified = asn1::oid!(1, 2, 840, 113549, 1, 1, 9);
                let is_default = *p_source.oid() == p_specified
                    && matches!(&p_source.params, AlgorithmParameters::Other(_, param) if param.as_ref().map_or(true, |t| t.data().is_empty()));
                if !is_default {
                    return Err(SmimeError::UnsupportedKeyEncryptionAlg {
                        alg: format!("non-default OAEP pSourceFunc: {}", p_source.oid()),
                    });
                }
            }
            let mgf_hash_oid = oaep_params.mask_gen_algorithm.params.oid();
            let hash_oid = oaep_params.hash_algorithm.oid();
            if mgf_hash_oid != hash_oid {
                return Err(SmimeError::UnsupportedKeyEncryptionAlg {
                    alg: format!("RSAES-OAEP MGF1 hash ({}) differs from hashFunc ({})", mgf_hash_oid, hash_oid),
                });
            }
            fn oaep_decrypt<D: sha2::Digest + sha2::digest::FixedOutputReset>(
                key: &RsaPrivateKey,
                ct: &[u8],
            ) -> Result<Vec<u8>, SmimeError> {
                key.decrypt(Oaep::<D>::new(), ct).map_err(|e| SmimeError::DecryptionFailed { err: e.to_string() })
            }
            match &oaep_params.hash_algorithm.params {
                AlgorithmParameters::Sha1(_) => {
                    warnings.push(SmimeError::WeakKeyEncryptionAlg { alg: "RSAES-OAEP with SHA-1".into() });
                    oaep_decrypt::<sha1::Sha1>(&private_key, encrypted_key)
                }
                AlgorithmParameters::Sha256(_) => oaep_decrypt::<sha2::Sha256>(&private_key, encrypted_key),
                AlgorithmParameters::Sha384(_) => oaep_decrypt::<sha2::Sha384>(&private_key, encrypted_key),
                AlgorithmParameters::Sha512(_) => oaep_decrypt::<sha2::Sha512>(&private_key, encrypted_key),
                other => Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("RSAES-OAEP with unsupported hash: {:?}", other) }),
            }
        }
        other => Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("{:?}", other) }),
    }?;
    Ok((cek, warnings))
}

/// Decrypt the CEK via ECDH key agreement (KARI).
/// Per RFC 5753 §3.1.3 (NIST curves), RFC 8418 (X25519/X448),
/// and RFC 3394 (AES key wrap).
fn decrypt_kari_cek(
    private_key_der: &[u8],
    kari: &KeyAgreeRecipientInfo,
    cert: &crate::cryptography_x509::certificate::Certificate,
) -> Result<(Vec<u8>, Vec<SmimeError>), SmimeError> {
    let mut warnings = Vec::new();
    use crate::cryptography_x509::oid;
    use der::Decode as _;
    use p256::pkcs8::AssociatedOid as _;
    use p256::pkcs8::DecodePrivateKey as _;
    use rsa::pkcs8::PrivateKeyInfoRef;

    let originator_key = match &kari.originator {
        OriginatorIdentifierOrKey::OriginatorKey(key) => key,
        _ => return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: "KARI originator must be originatorKey for ECDH".into() }),
    };
    let ephemeral_pubkey_bytes = originator_key.public_key.as_bytes();

    let ukm = kari.ukm.map(|u| u.to_vec());

    let kea = &kari.key_encryption_algorithm;

    // Determine KDF from key agreement OID (RFC 5753 §7.1.4 / RFC 8418 §7)
    let kea_oid = kea.oid();
    let kdf = identify_kdf(kea_oid)?;
    if matches!(&kdf, Kdf::X963(KdfHash::Sha1)) {
        warnings.push(SmimeError::WeakKeyEncryptionAlg { alg: "X9.63-KDF with SHA-1".into() });
    }

    // Extract KeyWrapAlgorithm OID from keyEncryptionAlgorithm parameters
    let wrap_alg_oid = extract_wrap_algorithm_oid(kea)?;
    let kek_len = aes_wrap_key_len(&wrap_alg_oid)?;

    // Identify key type from PKCS#8 PrivateKeyInfo algorithm
    let pki =
        PrivateKeyInfoRef::from_der(private_key_der).map_err(|e| SmimeError::PrivateKeyParseFailed { err: format!("PKCS#8: {}", e) })?;
    let key_alg_oid = pki.algorithm.oid;

    let is_x25519 = key_alg_oid.to_string() == oid::X25519_OID.to_string();

    let z: Vec<u8> = if is_x25519 {
        // RFC 8418: X25519 key agreement
        let sk_bytes: [u8; 32] = extract_x25519_private_key(pki.private_key.into())?;
        let pk_bytes: [u8; 32] = ephemeral_pubkey_bytes.try_into().map_err(|_| SmimeError::DecryptionFailed {
            err: format!("X25519 public key must be 32 bytes, got {}", ephemeral_pubkey_bytes.len()),
        })?;
        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
        let pk = x25519_dalek::PublicKey::from(pk_bytes);
        let shared = sk.diffie_hellman(&pk);
        // RFC 7748 §6: check for all-zero shared secret
        use p256::elliptic_curve::subtle::ConstantTimeEq;
        if shared.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(SmimeError::DecryptionFailed { err: "X25519 shared secret is all-zero".into() });
        }
        shared.as_bytes().to_vec()
    } else {
        // NIST curves (RFC 5753)
        let curve_oid =
            pki.algorithm.parameters_oid().map_err(|e| SmimeError::PrivateKeyParseFailed { err: format!("EC curve OID: {}", e) })?;

        // Reject cofactor DH OIDs for any curve where we cannot guarantee h=1.
        if is_cofactor_dh(kea_oid) {
            let is_prime_order = matches!(curve_oid,
                oid if oid == p256::NistP256::OID
                    || oid == p384::NistP384::OID
                    || oid == p521::NistP521::OID
            );
            if !is_prime_order {
                return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("cofactor DH not supported for curve {}", curve_oid) });
            }
        }

        macro_rules! ecdh {
            ($mod:ident, $label:expr) => {{
                let sk = $mod::SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|e| SmimeError::PrivateKeyParseFailed { err: format!("{}: {}", $label, e) })?;
                let pk = $mod::PublicKey::from_sec1_bytes(ephemeral_pubkey_bytes)
                    .map_err(|e| SmimeError::DecryptionFailed { err: format!("invalid {} point: {}", $label, e) })?;
                $mod::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()
            }};
        }
        match curve_oid {
            oid if oid == p256::NistP256::OID => ecdh!(p256, "P-256"),
            oid if oid == p384::NistP384::OID => ecdh!(p384, "P-384"),
            oid if oid == p521::NistP521::OID => ecdh!(p521, "P-521"),
            _ => return Err(SmimeError::PrivateKeyParseFailed { err: format!("unsupported EC curve: {}", curve_oid) }),
        }
    };

    // ECC-CMS-SharedInfo (RFC 5753 §7.2, also used by RFC 8418)
    let shared_info = build_ecc_cms_shared_info(&wrap_alg_oid, ukm.as_deref(), kek_len)?;

    // Derive KEK using the appropriate KDF
    let kek = match kdf {
        Kdf::X963(hash) => x963_kdf(hash, &z, &shared_info, kek_len)?,
        Kdf::Hkdf(hash) => hkdf_derive(hash, &z, ukm.as_deref(), &shared_info, kek_len)?,
    };

    // Try each RecipientEncryptedKey - a single KARI may contain keys for
    // multiple recipients sharing the same ephemeral key (RFC 5652 §6.2.2).
    // Skip recipients whose identifier does not match the certificate.
    let mut last_err = None;
    for rek in kari.recipient_encrypted_keys.unwrap_read().clone() {
        use crate::cryptography_x509::pkcs7::KeyAgreeRecipientIdentifier;
        let matches = match &rek.rid {
            KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias) => ias_matches_cert(ias, cert),
            KeyAgreeRecipientIdentifier::RKeyId(rkid) => ski_matches_cert(rkid.subject_key_identifier, cert),
        };
        if !matches {
            continue;
        }
        match aes_key_unwrap(&kek, kek_len, rek.encrypted_key) {
            Ok(cek) => return Ok((cek, warnings)),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| SmimeError::DecryptionFailed { err: "KARI has no RecipientEncryptedKeys".into() }))
}

/// Extract raw 32-byte X25519 private key from PKCS#8 PrivateKeyInfo.
/// The private key is an OCTET STRING wrapping the 32-byte scalar.
fn extract_x25519_private_key(pkcs8_private_key: &[u8]) -> Result<[u8; 32], SmimeError> {
    let inner: &[u8] = asn1::parse_single(pkcs8_private_key)
        .map_err(|e| SmimeError::PrivateKeyParseFailed { err: format!("X25519 private key OCTET STRING: {}", e) })?;
    inner
        .try_into()
        .map_err(|_| SmimeError::PrivateKeyParseFailed { err: format!("X25519 private key must be 32 bytes, got {}", inner.len()) })
}

/// Decrypt the CEK via password-based key management (PWRI).
/// Per RFC 3211 (password-based key wrapping) and RFC 8018 (PBKDF2).
pub fn decrypt_pwri_cek(
    password: Option<&str>,
    pwri: &crate::cryptography_x509::pkcs7::PasswordRecipientInfo,
) -> Result<(Vec<u8>, Vec<SmimeError>), SmimeError> {
    let mut warnings = Vec::new();
    let password = password.ok_or_else(|| SmimeError::DecryptionFailed { err: "password required for PasswordRecipientInfo".into() })?;

    let inner_alg = extract_pwri_inner_algorithm(&pwri.key_encryption_algorithm)?;
    let kek_len = match &inner_alg.params {
        AlgorithmParameters::Aes128Cbc(_) => 16,
        AlgorithmParameters::Aes192Cbc(_) => 24,
        AlgorithmParameters::Aes256Cbc(_) => 32,
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(_) => 24,
        other => return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("PWRI cipher: {:?}", other) }),
    };

    // Derive KEK from password via PBKDF2 (RFC 8018)
    let kda = pwri
        .key_derivation_algorithm
        .as_ref()
        .ok_or_else(|| SmimeError::UnsupportedKeyEncryptionAlg { alg: "PWRI without keyDerivationAlgorithm".into() })?;
    let kek = match &kda.params {
        AlgorithmParameters::Pbkdf2(params) => {
            if params.iteration_count < 100_000 {
                warnings.push(SmimeError::Pbkdf2LowIterationCount { iterations: params.iteration_count });
            }
            if params.iteration_count > 100_000_000 {
                return Err(SmimeError::DecryptionFailed {
                    err: format!("PBKDF2 iteration count {} is unreasonably high", params.iteration_count),
                });
            }
            let rounds = u32::try_from(params.iteration_count).map_err(|_| SmimeError::DecryptionFailed {
                err: format!("PBKDF2 iteration count {} exceeds u32", params.iteration_count),
            })?;
            let mut kek = vec![0u8; kek_len];
            match &params.prf.params {
                AlgorithmParameters::HmacWithSha1(_) => {
                    warnings.push(SmimeError::WeakKeyEncryptionAlg { alg: "PBKDF2 with HMAC-SHA-1".into() });
                    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), params.salt, rounds, &mut kek);
                }
                AlgorithmParameters::HmacWithSha256(_) => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), params.salt, rounds, &mut kek);
                }
                AlgorithmParameters::HmacWithSha384(_) => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password.as_bytes(), params.salt, rounds, &mut kek);
                }
                AlgorithmParameters::HmacWithSha512(_) => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), params.salt, rounds, &mut kek);
                }
                other => return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("PBKDF2 PRF: {:?}", other) }),
            }
            kek
        }
        other => return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("PWRI KDF: {:?}", other) }),
    };

    // RFC 3211 §2.3.2 key unwrap
    let decrypted = match &inner_alg.params {
        AlgorithmParameters::Aes128Cbc(iv) => pwri_unwrap_cek::<Aes128>(&kek, iv, pwri.encrypted_key)?,
        AlgorithmParameters::Aes192Cbc(iv) => pwri_unwrap_cek::<Aes192>(&kek, iv, pwri.encrypted_key)?,
        AlgorithmParameters::Aes256Cbc(iv) => pwri_unwrap_cek::<Aes256>(&kek, iv, pwri.encrypted_key)?,
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(iv) => pwri_unwrap_cek::<des::TdesEde3>(&kek, iv, pwri.encrypted_key)?,
        _ => unreachable!(),
    };

    // RFC 3211 §2.3.1: format = length(1) || check(3) || CEK || padding
    // Check value = bitwise complement of the first three bytes of the CEK.
    if decrypted.len() < 4 {
        return Err(SmimeError::DecryptionFailed { err: "PWRI unwrap produced output too short".into() });
    }
    let cek_len = decrypted[0] as usize;
    if cek_len + 4 > decrypted.len() {
        return Err(SmimeError::DecryptionFailed { err: format!("PWRI CEK length {} exceeds unwrapped data", cek_len) });
    }
    if cek_len < 3 {
        return Err(SmimeError::DecryptionFailed { err: format!("PWRI CEK length {} too short for check value", cek_len) });
    }
    let check = &decrypted[1..4];
    let cek = &decrypted[4..4 + cek_len];
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    if check.ct_eq(&[!cek[0], !cek[1], !cek[2]]).unwrap_u8() == 0 {
        return Err(SmimeError::DecryptionFailed { err: "PWRI check value mismatch".into() });
    }
    Ok((cek.to_vec(), warnings))
}

/// RFC 3211 §2.3.2: unwrap a CEK using CBC double-decrypt.
fn pwri_unwrap_cek<C>(kek: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, SmimeError>
where
    C: cbc::cipher::BlockCipherDecrypt + cbc::cipher::KeyInit,
{
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};

    let bs = C::block_size();
    if ct.len() < 2 * bs || ct.len() % bs != 0 {
        return Err(SmimeError::DecryptionFailed { err: "PWRI encrypted key too short or not block-aligned".into() });
    }
    let n = ct.len() / bs;

    let decrypt = |key: &[u8], iv: &[u8], data: &mut [u8]| -> Result<(), SmimeError> {
        cbc::Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|e| SmimeError::DecryptionFailed { err: e.to_string() })?
            .decrypt_padded::<NoPadding>(data)
            .map_err(|e| SmimeError::DecryptionFailed { err: e.to_string() })?;
        Ok(())
    };

    // Step 1: Using the (n-1)'th block as IV, decrypt the n'th block
    let step1_iv = &ct[(n - 2) * bs..(n - 1) * bs];
    let mut last_block = ct[(n - 1) * bs..].to_vec();
    decrypt(kek, step1_iv, &mut last_block)?;

    // Step 2: Using decrypted last block as IV, decrypt blocks 0..n-2
    let mut buf = ct[..(n - 1) * bs].to_vec();
    decrypt(kek, &last_block, &mut buf)?;

    // Reassemble and decrypt the inner layer with original IV
    buf.extend_from_slice(&last_block);
    decrypt(kek, iv, &mut buf)?;
    Ok(buf)
}

/// Extract the inner AlgorithmIdentifier from PWRI-KEK keyEncryptionAlgorithm parameters.
fn extract_pwri_inner_algorithm<'a>(
    kea: &'a crate::cryptography_x509::common::AlgorithmIdentifier<'a>,
) -> Result<crate::cryptography_x509::common::AlgorithmIdentifier<'a>, SmimeError> {
    let params_tlv = match &kea.params {
        AlgorithmParameters::Other(_, Some(tlv)) => tlv,
        _ => return Err(SmimeError::DecryptionFailed { err: "PWRI-KEK missing algorithm params".into() }),
    };
    asn1::parse_single(params_tlv.full_data()).map_err(|e| SmimeError::DecryptionFailed { err: format!("PWRI inner alg: {}", e) })
}

/// Decrypt the CEK via pre-shared symmetric key (KEKRI).
/// Per RFC 5652 §6.2.3.
fn decrypt_kekri_cek(
    kek: Option<&[u8]>,
    kekri: &crate::cryptography_x509::pkcs7::KEKRecipientInfo,
) -> Result<(Vec<u8>, Vec<SmimeError>), SmimeError> {
    let kek = kek.ok_or_else(|| SmimeError::DecryptionFailed { err: "pre-shared key required for KEKRecipientInfo".into() })?;
    let wrap_oid = kekri.key_encryption_algorithm.oid();
    let kek_len = aes_wrap_key_len(wrap_oid)?;
    if kek.len() != kek_len {
        return Err(SmimeError::DecryptionFailed {
            err: format!("KEK length {} does not match algorithm (expected {})", kek.len(), kek_len),
        });
    }
    aes_key_unwrap(kek, kek_len, kekri.encrypted_key).map(|cek| (cek, vec![]))
}

pub fn ecdh_algorithm_name(oid: &asn1::ObjectIdentifier) -> String {
    use crate::cryptography_x509::oid;
    match *oid {
        oid::DH_STD_SHA1 => "dhSinglePass-stdDH-sha1kdf",
        oid::DH_STD_SHA224 => "dhSinglePass-stdDH-sha224kdf",
        oid::DH_STD_SHA256 => "dhSinglePass-stdDH-sha256kdf",
        oid::DH_STD_SHA384 => "dhSinglePass-stdDH-sha384kdf",
        oid::DH_STD_SHA512 => "dhSinglePass-stdDH-sha512kdf",
        oid::DH_COF_SHA1 => "dhSinglePass-cofactorDH-sha1kdf",
        oid::DH_COF_SHA224 => "dhSinglePass-cofactorDH-sha224kdf",
        oid::DH_COF_SHA256 => "dhSinglePass-cofactorDH-sha256kdf",
        oid::DH_COF_SHA384 => "dhSinglePass-cofactorDH-sha384kdf",
        oid::DH_COF_SHA512 => "dhSinglePass-cofactorDH-sha512kdf",
        oid::DH_HKDF_SHA256 => "dhSinglePass-stdDH-hkdf-sha256",
        oid::DH_HKDF_SHA384 => "dhSinglePass-stdDH-hkdf-sha384",
        oid::DH_HKDF_SHA512 => "dhSinglePass-stdDH-hkdf-sha512",
        _ => return format!("ECDH ({})", oid),
    }
    .into()
}

enum KdfHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

enum Kdf {
    X963(KdfHash),
    Hkdf(KdfHash),
}

fn is_cofactor_dh(oid: &asn1::ObjectIdentifier) -> bool {
    use crate::cryptography_x509::oid;
    matches!(*oid, oid::DH_COF_SHA1 | oid::DH_COF_SHA224 | oid::DH_COF_SHA256 | oid::DH_COF_SHA384 | oid::DH_COF_SHA512)
}

fn identify_kdf(oid: &asn1::ObjectIdentifier) -> Result<Kdf, SmimeError> {
    use crate::cryptography_x509::oid;
    match *oid {
        oid::DH_STD_SHA1 | oid::DH_COF_SHA1 => Ok(Kdf::X963(KdfHash::Sha1)),
        oid::DH_STD_SHA224 | oid::DH_COF_SHA224 => Ok(Kdf::X963(KdfHash::Sha224)),
        oid::DH_STD_SHA256 | oid::DH_COF_SHA256 => Ok(Kdf::X963(KdfHash::Sha256)),
        oid::DH_STD_SHA384 | oid::DH_COF_SHA384 => Ok(Kdf::X963(KdfHash::Sha384)),
        oid::DH_STD_SHA512 | oid::DH_COF_SHA512 => Ok(Kdf::X963(KdfHash::Sha512)),
        oid::DH_HKDF_SHA256 => Ok(Kdf::Hkdf(KdfHash::Sha256)),
        oid::DH_HKDF_SHA384 => Ok(Kdf::Hkdf(KdfHash::Sha384)),
        oid::DH_HKDF_SHA512 => Ok(Kdf::Hkdf(KdfHash::Sha512)),
        _ => Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("unsupported ECDH KDF scheme: {}", oid) }),
    }
}

fn extract_wrap_algorithm_oid(
    kea: &crate::cryptography_x509::common::AlgorithmIdentifier<'_>,
) -> Result<asn1::ObjectIdentifier, SmimeError> {
    let params_tlv = match &kea.params {
        AlgorithmParameters::Other(_, Some(tlv)) => tlv,
        _ => return Err(SmimeError::DecryptionFailed { err: "KARI missing KeyWrapAlgorithm params".into() }),
    };
    let wrap_alg: crate::cryptography_x509::common::AlgorithmIdentifier<'_> =
        asn1::parse_single(params_tlv.full_data()).map_err(|e| SmimeError::DecryptionFailed { err: format!("wrap alg parse: {}", e) })?;
    Ok(wrap_alg.oid().clone())
}

fn aes_wrap_key_len(oid: &asn1::ObjectIdentifier) -> Result<usize, SmimeError> {
    use crate::cryptography_x509::oid;
    match *oid {
        oid::AES128_WRAP => Ok(16),
        oid::AES192_WRAP => Ok(24),
        oid::AES256_WRAP => Ok(32),
        _ => Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: format!("unsupported key wrap algorithm: {}", oid) }),
    }
}

fn build_ecc_cms_shared_info(wrap_oid: &asn1::ObjectIdentifier, ukm: Option<&[u8]>, kek_len: usize) -> Result<Vec<u8>, SmimeError> {
    use crate::cryptography_x509::pkcs7::EccCmsSharedInfo;

    let key_info = crate::cryptography_x509::common::AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: AlgorithmParameters::Other(wrap_oid.clone(), None),
    };
    let supp_pub_info = ((kek_len * 8) as u32).to_be_bytes();
    let shared_info = EccCmsSharedInfo { key_info, entity_u_info: ukm, supp_pub_info: &supp_pub_info };
    asn1::write_single(&shared_info).map_err(|e| SmimeError::DecryptionFailed { err: format!("SharedInfo DER: {}", e) })
}

fn x963_kdf(hash: KdfHash, z: &[u8], shared_info: &[u8], key_len: usize) -> Result<Vec<u8>, SmimeError> {
    let mut key = vec![0u8; key_len];
    macro_rules! do_kdf {
        ($hasher:ty) => {
            ansi_x963_kdf::derive_key_into::<$hasher>(z, shared_info, &mut key)
                .map_err(|_| SmimeError::DecryptionFailed { err: "X9.63-KDF output too long".into() })?
        };
    }
    match hash {
        KdfHash::Sha1 => do_kdf!(sha1::Sha1),
        KdfHash::Sha224 => do_kdf!(sha2::Sha224),
        KdfHash::Sha256 => do_kdf!(sha2::Sha256),
        KdfHash::Sha384 => do_kdf!(sha2::Sha384),
        KdfHash::Sha512 => do_kdf!(sha2::Sha512),
    }
    Ok(key)
}

/// HKDF key derivation (RFC 5869, used by RFC 8418 for X25519/X448).
/// salt = ukm (or empty), IKM = shared secret, info = DER(ECC-CMS-SharedInfo).
fn hkdf_derive(hash: KdfHash, z: &[u8], ukm: Option<&[u8]>, shared_info: &[u8], key_len: usize) -> Result<Vec<u8>, SmimeError> {
    use hkdf::Hkdf;
    let salt = ukm.unwrap_or(&[]);
    let mut okm = vec![0u8; key_len];
    macro_rules! do_hkdf {
        ($hasher:ty) => {{
            let hk = Hkdf::<$hasher>::new(Some(salt), z);
            hk.expand(shared_info, &mut okm).map_err(|e| SmimeError::DecryptionFailed { err: format!("HKDF expand: {}", e) })?;
        }};
    }
    match hash {
        KdfHash::Sha256 => do_hkdf!(sha2::Sha256),
        KdfHash::Sha384 => do_hkdf!(sha2::Sha384),
        KdfHash::Sha512 => do_hkdf!(sha2::Sha512),
        _ => return Err(SmimeError::UnsupportedKeyEncryptionAlg { alg: "HKDF only supports SHA-256/384/512".into() }),
    }
    Ok(okm)
}

fn aes_key_unwrap(kek: &[u8], kek_len: usize, wrapped_key: &[u8]) -> Result<Vec<u8>, SmimeError> {
    use aes_kw::KeyInit;
    let mut output = vec![0u8; wrapped_key.len().saturating_sub(8)];
    macro_rules! do_unwrap {
        ($kw_type:ty) => {
            <$kw_type>::new_from_slice(kek)
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("KEK init: {}", e) })?
                .unwrap_key(wrapped_key, &mut output)
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("AES unwrap: {}", e) })?
        };
    }
    match kek_len {
        16 => {
            do_unwrap!(aes_kw::KwAes128);
        }
        24 => {
            do_unwrap!(aes_kw::KwAes192);
        }
        32 => {
            do_unwrap!(aes_kw::KwAes256);
        }
        _ => return Err(SmimeError::DecryptionFailed { err: format!("Invalid KEK length: {}", kek_len) }),
    }
    Ok(output)
}

/// Decrypt a CMS AuthEnvelopedData structure (RFC 5083).
/// Uses AEAD ciphers (AES-GCM per RFC 5084, AES-CCM per RFC 5084).
pub fn decrypt_auth_enveloped_data(
    auth_enveloped: &AuthEnvelopedData,
    keys: &DecryptionKeys,
) -> Result<(Option<Vec<u8>>, Vec<SmimeError>), SmimeError> {
    let mut warnings = Vec::new();
    let ciphertext = match auth_enveloped.auth_encrypted_content_info.encrypted_content {
        Some(ct) => ct,
        None => return Ok((None, warnings)),
    };

    if auth_enveloped.auth_encrypted_content_info.content_type != PKCS7_DATA_OID {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("unexpected contentType: {}", auth_enveloped.auth_encrypted_content_info.content_type),
        });
    }

    let outer_cea = &auth_enveloped.auth_encrypted_content_info.content_encryption_algorithm.params;
    let (cea, inner_alg_der) = resolve_cek_hkdf(outer_cea)?;

    let expected_key_len = match &cea {
        AlgorithmParameters::Aes128Gcm(_) | AlgorithmParameters::Aes128Ccm(_) => 16usize,
        AlgorithmParameters::Aes192Gcm(_) | AlgorithmParameters::Aes192Ccm(_) => 24usize,
        AlgorithmParameters::Aes256Gcm(_) | AlgorithmParameters::Aes256Ccm(_) => 32usize,
        other => return Err(SmimeError::UnsupportedContentEncryptionAlg { alg: format!("{:?}", other) }),
    };

    let (cek, cek_warnings) = recover_cek(keys, &auth_enveloped.recipient_infos, expected_key_len)?;
    warnings.extend(cek_warnings);

    let key = if let Some(ref der) = inner_alg_der { cms_cek_hkdf_sha256(&cek, der)? } else { cek };

    // AAD = DER-encoded authAttrs if present, else empty
    let aad = match &auth_enveloped.auth_attrs {
        Some(attrs) => asn1::write_single(attrs).map_err(|e| SmimeError::DecryptionFailed { err: format!("authAttrs DER: {}", e) })?,
        None => vec![],
    };

    // AEAD decrypt
    match &cea {
        AlgorithmParameters::Aes128Gcm(p) | AlgorithmParameters::Aes192Gcm(p) | AlgorithmParameters::Aes256Gcm(p) => {
            decrypt_aes_gcm(&key, p.nonce, &aad, ciphertext, auth_enveloped.mac, p.icv_len as usize).map(|pt| (Some(pt), warnings))
        }
        #[cfg(feature = "decrypt-ccm")]
        AlgorithmParameters::Aes128Ccm(p) | AlgorithmParameters::Aes192Ccm(p) | AlgorithmParameters::Aes256Ccm(p) => {
            decrypt_aes_ccm(&key, p.nonce, &aad, ciphertext, auth_enveloped.mac, p.icv_len as usize).map(|pt| (Some(pt), warnings))
        }
        _ => return Err(SmimeError::UnsupportedContentEncryptionAlg { alg: format!("{:?}", cea) }),
    }
}

fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8], tag_len: usize) -> Result<Vec<u8>, SmimeError> {
    use aes_gcm::{KeyInit, aead::AeadInOut};

    let nonce: &[u8; 12] =
        nonce.try_into().map_err(|_| SmimeError::DecryptionFailed { err: format!("GCM nonce must be 12 bytes, got {}", nonce.len()) })?;
    if tag.len() != tag_len {
        return Err(SmimeError::DecryptionFailed { err: format!("GCM tag length {} does not match icvLen {}", tag.len(), tag_len) });
    }
    // RFC 5084 §3.2: AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16).
    // The aes-gcm crate requires the tag length as a type-level param, so dispatch via macros.
    if !(12..=16).contains(&tag_len) {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("AES-GCM ICVlen {} not valid per RFC 5084 (must be 12..16)", tag_len),
        });
    }

    let mut buf = ciphertext.to_vec();
    macro_rules! gcm_decrypt {
        ($aes:ty, $tag_ty:ty, $tag_len_val:literal) => {{
            type C = aes_gcm::AesGcm<$aes, aes_gcm::aead::consts::U12, $tag_ty>;
            let t: &[u8; $tag_len_val] = tag.try_into().unwrap();
            C::new_from_slice(key)
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("AES-GCM init: {}", e) })?
                .decrypt_inout_detached(nonce.into(), aad, (&mut buf[..]).into(), t.into())
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("AES-GCM: {}", e) })?
        }};
    }
    macro_rules! gcm_tag_dispatch {
        ($aes:ty) => {
            match tag_len {
                12 => gcm_decrypt!($aes, aes_gcm::aead::consts::U12, 12),
                13 => gcm_decrypt!($aes, aes_gcm::aead::consts::U13, 13),
                14 => gcm_decrypt!($aes, aes_gcm::aead::consts::U14, 14),
                15 => gcm_decrypt!($aes, aes_gcm::aead::consts::U15, 15),
                16 => gcm_decrypt!($aes, aes_gcm::aead::consts::U16, 16),
                _ => unreachable!(),
            }
        };
    }
    match key.len() {
        16 => gcm_tag_dispatch!(Aes128),
        24 => gcm_tag_dispatch!(Aes192),
        32 => gcm_tag_dispatch!(Aes256),
        _ => {
            return Err(SmimeError::UnsupportedContentEncryptionAlg {
                alg: format!("AES-GCM with {}-bit key not supported", key.len() * 8),
            });
        }
    }
    Ok(buf)
}

#[cfg(feature = "decrypt-ccm")]
fn decrypt_aes_ccm(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8], tag_len: usize) -> Result<Vec<u8>, SmimeError> {
    use ccm::{KeyInit, aead::AeadInOut};

    if tag.len() != tag_len {
        return Err(SmimeError::DecryptionFailed { err: format!("CCM tag length {} does not match icvLen {}", tag.len(), tag_len) });
    }

    // RFC 5084 §3.1 allows ICVlen 4..16, but short tags make forgery cheap and the
    // sender chooses the length, so require at least the RFC 5084 default of 12.
    // Nonce must be 7..13 octets. The ccm crate requires these as type-level params,
    // so dispatch via nested macros.
    if !matches!(tag_len, 12 | 14 | 16) {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("AES-CCM ICVlen {} not supported (must be 12, 14 or 16)", tag_len),
        });
    }
    if !(7..=13).contains(&nonce.len()) {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("AES-CCM nonce length {} not valid per RFC 5084 (must be 7..13)", nonce.len()),
        });
    }
    if !matches!(key.len(), 16 | 32) {
        return Err(SmimeError::UnsupportedContentEncryptionAlg {
            alg: format!("AES-CCM key length {} not supported (must be 128 or 256 bit)", key.len() * 8),
        });
    }

    let mut buf = ciphertext.to_vec();
    macro_rules! ccm_decrypt {
        ($aes:ty, $tag_ty:ty, $nonce_ty:ty, $nonce_len:literal, $tag_len_val:literal) => {{
            type C = ccm::Ccm<$aes, $tag_ty, $nonce_ty>;
            let n: &[u8; $nonce_len] = nonce.try_into().unwrap();
            let t: &[u8; $tag_len_val] = tag.try_into().unwrap();
            C::new_from_slice(key)
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("AES-CCM init: {}", e) })?
                .decrypt_inout_detached(n.into(), aad, (&mut buf[..]).into(), t.into())
                .map_err(|e| SmimeError::DecryptionFailed { err: format!("AES-CCM: {}", e) })?
        }};
    }
    // Dispatch over all supported (key, tag, nonce) triples
    macro_rules! ccm_nonce_dispatch {
        ($aes:ty, $tag_ty:ty, $tag_len_val:literal) => {
            match nonce.len() {
                7 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U7, 7, $tag_len_val),
                8 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U8, 8, $tag_len_val),
                9 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U9, 9, $tag_len_val),
                10 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U10, 10, $tag_len_val),
                11 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U11, 11, $tag_len_val),
                12 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U12, 12, $tag_len_val),
                13 => ccm_decrypt!($aes, $tag_ty, ccm::consts::U13, 13, $tag_len_val),
                _ => unreachable!(),
            }
        };
    }
    macro_rules! ccm_tag_dispatch {
        ($aes:ty) => {
            match tag_len {
                12 => ccm_nonce_dispatch!($aes, ccm::consts::U12, 12),
                14 => ccm_nonce_dispatch!($aes, ccm::consts::U14, 14),
                16 => ccm_nonce_dispatch!($aes, ccm::consts::U16, 16),
                _ => unreachable!(),
            }
        };
    }
    match key.len() {
        16 => ccm_tag_dispatch!(Aes128),
        32 => ccm_tag_dispatch!(Aes256),
        _ => unreachable!(),
    }
    Ok(buf)
}

fn decrypt_cbc<C: cbc::cipher::BlockCipherDecrypt + cbc::cipher::KeyInit>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SmimeError> {
    let mut buf = ciphertext.to_vec();
    let decryptor = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|e| SmimeError::DecryptionFailed { err: e.to_string() })?;
    let pt = decryptor.decrypt_padded::<Pkcs7>(&mut buf).map_err(|e| SmimeError::DecryptionFailed { err: e.to_string() })?;
    Ok(pt.to_vec())
}

/// RFC 9709 §2: Derive CEK' from CEK using HKDF-SHA256.
/// salt = "The Cryptographic Message Syntax", info = DER-encoded AlgorithmIdentifier.
pub fn cms_cek_hkdf_sha256(ikm: &[u8], info: &[u8]) -> Result<Vec<u8>, SmimeError> {
    if ikm.len() > 8160 {
        return Err(SmimeError::DecryptionFailed { err: format!("CEK length {} exceeds RFC 9709 maximum of 8160", ikm.len()) });
    }
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"The Cryptographic Message Syntax"), ikm);
    let mut okm = vec![0u8; ikm.len()];
    hkdf.expand(info, &mut okm).map_err(|e| SmimeError::DecryptionFailed { err: format!("HKDF-Expand: {}", e) })?;
    Ok(okm)
}

pub fn decrypt_aes_cbc(key: &[u8], expected_key_len: usize, iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, SmimeError> {
    match expected_key_len {
        16 => decrypt_cbc::<Aes128>(key, iv, ciphertext),
        24 => decrypt_cbc::<Aes192>(key, iv, ciphertext),
        32 => decrypt_cbc::<Aes256>(key, iv, ciphertext),
        _ => Err(SmimeError::DecryptionFailed { err: format!("Invalid AES key length: {} bytes", expected_key_len) }),
    }
}

#[cfg(feature = "decrypt-3des")]
pub fn decrypt_3des_cbc(key: &[u8], iv: &[u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>, SmimeError> {
    decrypt_cbc::<des::TdesEde3>(key, iv, ciphertext)
}
