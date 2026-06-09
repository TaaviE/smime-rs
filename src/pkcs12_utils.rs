use crate::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use crate::cryptography_x509::pkcs7::{Content, ContentInfo};
use crate::cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;
use crate::cryptography_x509::pkcs12::{KEY_BAG_OID, MacData, Pfx, SHROUDED_KEY_BAG_OID};

// SafeBag read path. Upstream pyca-cryptography only constructs PKCS#12, so its
// SafeBag/BagValue in cryptography_x509::pkcs12 are write-only; these mirror them
// for the bag types we extract keys from. bag_id, bag_attributes and the Other
// fields exist to drive parsing but are not read.
#[derive(asn1::Asn1Read)]
#[allow(dead_code)]
struct SafeBag<'a> {
    bag_id: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(bag_id)]
    bag_value: BagValue<'a>,
    bag_attributes: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1DefinedByRead)]
#[allow(dead_code)]
enum BagValue<'a> {
    #[defined_by(KEY_BAG_OID)]
    KeyBag(asn1::Explicit<asn1::Tlv<'a>, 0>),
    #[defined_by(SHROUDED_KEY_BAG_OID)]
    ShroudedKeyBag(asn1::Explicit<EncryptedPrivateKeyInfo<'a>, 0>),
    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

/// Extract the PKCS#8 private key DER from a PKCS#12 (.p12/.pfx) file.
pub fn extract_private_key_from_p12(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let pfx: Pfx = asn1::parse_single(data).map_err(|e| format!("PFX parse: {}", e))?;

    // PFX.authSafe is a ContentInfo of type id-data wrapping the AuthenticatedSafe DER.
    let auth_safe_bytes: &[u8] = match &pfx.auth_safe.content {
        Content::Data(Some(d)) => d.as_inner(),
        _ => return Err("PKCS#12 authSafe is not id-data".into()),
    };

    // RFC 7292 paragraph 4: verify MAC if present
    if let Some(mac_data) = &pfx.mac_data {
        verify_pfx_mac(mac_data, auth_safe_bytes, password)?;
    } else {
        // MacData is OPTIONAL in RFC 7292 because integrity may instead come from
        // public-key mode (authSafe as SignedData), which we reject above - so this
        // branch means no integrity protection at all. Mimics OpenSSL: a missing MAC
        // is allowed, only a present-but-invalid MAC is a hard failure.
        eprintln!("Warning: PKCS#12 file has no MAC - integrity cannot be verified");
    }

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    let auth_safe = asn1::parse_single::<asn1::SequenceOf<ContentInfo>>(auth_safe_bytes).map_err(|e| format!("auth_safe decode: {}", e))?;

    for ci in auth_safe {
        match &ci.content {
            // id-data: an OCTET STRING wrapping the SafeContents DER
            Content::Data(Some(d)) => {
                if let Some(key) = find_key_in_safe_contents(d.as_inner(), password)? {
                    return Ok(key);
                }
            }
            Content::EncryptedData(enc) => {
                let eci = &enc.as_inner().encrypted_content_info;
                let ciphertext = eci.encrypted_content.ok_or("EncryptedData has no content")?;
                let plaintext = pbes2_decrypt(&eci.content_encryption_algorithm, password, ciphertext)?;
                if let Some(key) = find_key_in_safe_contents(&plaintext, password)? {
                    return Ok(key);
                }
            }
            _ => {}
        }
    }

    Err("No private key found in PKCS#12".into())
}

fn find_key_in_safe_contents(der: &[u8], password: &str) -> Result<Option<Vec<u8>>, String> {
    let bags = asn1::parse_single::<asn1::SequenceOf<SafeBag>>(der).map_err(|e| format!("SafeContents decode: {}", e))?;
    for bag in bags {
        match bag.bag_value {
            BagValue::ShroudedKeyBag(epki) => {
                let epki = epki.as_inner();
                let decrypted = pbes2_decrypt(&epki.encryption_algorithm, password, epki.encrypted_data)?;
                return Ok(Some(decrypted));
            }
            BagValue::KeyBag(key) => return Ok(Some(key.as_inner().full_data().to_vec())),
            BagValue::Other(..) => {}
        }
    }
    Ok(None)
}

fn pbes2_decrypt(alg: &AlgorithmIdentifier, password: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes::{Aes128, Aes192, Aes256};
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

    let pbes2 = match &alg.params {
        AlgorithmParameters::Pbes2(p) => p,
        _ => return Err(format!("Unsupported PBE scheme: {} (only PBES2 supported)", alg.oid())),
    };

    let pbkdf2 = match &pbes2.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(p) => p,
        _ => return Err(format!("Unsupported PBES2 KDF: {} (only PBKDF2 supported)", pbes2.key_derivation_func.oid())),
    };

    let enc = &pbes2.encryption_scheme;
    let (key_len, iv): (usize, &[u8]) = match &enc.params {
        AlgorithmParameters::Aes128Cbc(iv) => (16, iv),
        AlgorithmParameters::Aes192Cbc(iv) => (24, iv),
        AlgorithmParameters::Aes256Cbc(iv) => (32, iv),
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(iv) => (24, iv),
        _ => return Err(format!("Unsupported PBES2 cipher: {}", enc.oid())),
    };

    if pbkdf2.salt.len() < 8 {
        return Err(format!("PBKDF2 salt length {} is below minimum of 8 bytes", pbkdf2.salt.len()));
    }
    if pbkdf2.iteration_count > 100_000_000 {
        return Err(format!("PBKDF2 iteration count {} is unreasonably high", pbkdf2.iteration_count));
    }
    if pbkdf2.iteration_count < 100_000 {
        eprintln!("Warning: PBKDF2 iteration count {} is below recommended minimum of 100000", pbkdf2.iteration_count);
    }

    // RFC 8018 paragraph A.2: dispatch on the PRF (default is hmacWithSHA1)
    let rounds = pbkdf2.iteration_count as u32;
    let mut key = vec![0u8; key_len];
    match &pbkdf2.prf.params {
        AlgorithmParameters::HmacWithSha1(_) => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha224(_) => return Err("PBKDF2 with HMAC-SHA-224 not supported".to_owned()),
        AlgorithmParameters::HmacWithSha256(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha384(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha512(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        _ => return Err(format!("Unsupported PBKDF2 PRF: {}", pbkdf2.prf.oid())),
    };

    let mut buf = ciphertext.to_vec();
    macro_rules! do_decrypt {
        ($cipher:ty) => {
            cbc::Decryptor::<$cipher>::new_from_slices(&key, iv)
                .map_err(|e| format!("cipher init: {}", e))?
                .decrypt_padded::<Pkcs7>(&mut buf)
                .map_err(|e| format!("cipher decrypt: {}", e))?
                .to_vec()
        };
    }
    Ok(match &enc.params {
        AlgorithmParameters::Aes128Cbc(_) => do_decrypt!(Aes128),
        AlgorithmParameters::Aes192Cbc(_) => do_decrypt!(Aes192),
        AlgorithmParameters::Aes256Cbc(_) => do_decrypt!(Aes256),
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(_) => do_decrypt!(des::TdesEde3),
        _ => unreachable!(),
    })
}

/// Verify the PKCS#12 MAC over the authSafe content (RFC 7292 paragraph 4, Appendix B).
fn verify_pfx_mac(mac_data: &MacData, auth_safe_bytes: &[u8], password: &str) -> Result<(), String> {
    use pbkdf2::hmac::{Hmac, Mac, digest::KeyInit};

    let salt = mac_data.salt;
    if salt.len() < 8 {
        return Err(format!("PKCS#12 MAC salt length {} is below minimum of 8 bytes", salt.len()));
    }
    let iterations = mac_data.iterations;
    if iterations == 0 {
        return Err("PKCS#12 MAC iteration count 0 is invalid".to_owned());
    }
    if iterations > 100_000_000 {
        return Err(format!("PKCS#12 MAC iteration count {} is unreasonably high", iterations));
    }
    let rounds = iterations as i32;
    let expected_mac = mac_data.mac.digest;

    // RFC 7292 Appendix B: derive MAC key using PKCS#12 KDF with id=3 (Mac)
    macro_rules! verify_mac {
        ($hash:ty, $mac_len:expr) => {{
            let mac_key = pkcs12::kdf::derive_key_utf8::<$hash>(password, salt, pkcs12::kdf::Pkcs12KeyType::Mac, rounds, $mac_len)
                .map_err(|e| format!("MAC key derivation: {}", e))?;
            let mut mac = Hmac::<$hash>::new_from_slice(&mac_key).map_err(|e| format!("HMAC init: {}", e))?;
            mac.update(auth_safe_bytes);
            mac.verify_slice(expected_mac).map_err(|_| "PKCS#12 MAC verification failed (wrong password or corrupted file)".to_string())
        }};
    }

    match &mac_data.mac.algorithm.params {
        AlgorithmParameters::Sha1(_) => verify_mac!(sha1::Sha1, 20),
        AlgorithmParameters::Sha256(_) => verify_mac!(sha2::Sha256, 32),
        AlgorithmParameters::Sha384(_) => verify_mac!(sha2::Sha384, 48),
        AlgorithmParameters::Sha512(_) => verify_mac!(sha2::Sha512, 64),
        _ => Err(format!("Unsupported MAC digest algorithm: {}", mac_data.mac.algorithm.oid())),
    }
}
