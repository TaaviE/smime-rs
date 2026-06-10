use crate::cryptography_x509::certificate::Certificate;
use crate::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use crate::cryptography_x509::extensions::BasicConstraints;
use crate::cryptography_x509::oid::BASIC_CONSTRAINTS_OID;
use crate::cryptography_x509::pkcs7::{Content, ContentInfo};
use crate::cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;
use crate::cryptography_x509::pkcs12::{CERT_BAG_OID, KEY_BAG_OID, MacData, Pfx, SHROUDED_KEY_BAG_OID, X509_CERTIFICATE_OID};

/// PKCS#12 read failure, classified so callers can distinguish bad credentials
/// (MAC mismatch, PBES2 unpad failure) from unsupported or malformed input.
#[derive(Debug)]
pub enum P12Error {
    WrongPassword(String),
    NoLeafCertificate,
    Other(String),
}

impl P12Error {
    pub fn into_message(self) -> String {
        match self {
            P12Error::WrongPassword(msg) | P12Error::Other(msg) => msg,
            P12Error::NoLeafCertificate => "No end-entity certificate found in PKCS#12".into(),
        }
    }
}

// SafeBag read path. Upstream pyca-cryptography only constructs PKCS#12, so its
// SafeBag/BagValue/CertBag in cryptography_x509::pkcs12 are write-only; these mirror
// them for the bag types we extract keys and certificates from. bag_id, bag_attributes
// and the Other fields exist to drive parsing but are not read.
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
    #[defined_by(CERT_BAG_OID)]
    CertBag(asn1::Explicit<CertBag<'a>, 0>),
    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

#[derive(asn1::Asn1Read)]
#[allow(dead_code)]
struct CertBag<'a> {
    cert_id: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(cert_id)]
    cert_value: CertType<'a>,
}

#[derive(asn1::Asn1DefinedByRead)]
#[allow(dead_code)]
enum CertType<'a> {
    #[defined_by(X509_CERTIFICATE_OID)]
    X509(asn1::Explicit<asn1::OctetStringEncoded<asn1::Tlv<'a>>, 0>),
    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

/// Parse a PKCS#12 (.p12/.pfx) file, verify its MAC if present, and return the
/// plaintext SafeContents DER of every readable AuthenticatedSafe entry.
fn open_safe_contents(data: &[u8], password: &str) -> Result<Vec<Vec<u8>>, P12Error> {
    let pfx: Pfx = asn1::parse_single(data).map_err(|e| P12Error::Other(format!("PFX parse: {}", e)))?;

    // PFX.authSafe is a ContentInfo of type id-data wrapping the AuthenticatedSafe DER.
    let auth_safe_bytes: &[u8] = match &pfx.auth_safe.content {
        Content::Data(Some(d)) => d.as_inner(),
        _ => return Err(P12Error::Other("PKCS#12 authSafe is not id-data".into())),
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
    let auth_safe = asn1::parse_single::<asn1::SequenceOf<ContentInfo>>(auth_safe_bytes)
        .map_err(|e| P12Error::Other(format!("auth_safe decode: {}", e)))?;

    let mut all_contents = Vec::new();
    for ci in auth_safe {
        match &ci.content {
            // id-data: an OCTET STRING wrapping the SafeContents DER
            Content::Data(Some(d)) => all_contents.push(d.as_inner().to_vec()),
            Content::EncryptedData(enc) => {
                let eci = &enc.as_inner().encrypted_content_info;
                let ciphertext = eci.encrypted_content.ok_or_else(|| P12Error::Other("EncryptedData has no content".into()))?;
                all_contents.push(pbes2_decrypt(&eci.content_encryption_algorithm, password, ciphertext)?);
            }
            _ => {}
        }
    }
    Ok(all_contents)
}

/// Extract the PKCS#8 private key DER from a PKCS#12 (.p12/.pfx) file.
pub fn extract_private_key_from_p12(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    for contents in open_safe_contents(data, password).map_err(P12Error::into_message)? {
        if let Some(key) = find_key_in_safe_contents(&contents, password).map_err(P12Error::into_message)? {
            return Ok(key);
        }
    }
    Err("No private key found in PKCS#12".into())
}

/// Extract the first end-entity (non-CA) certificate DER from a PKCS#12 (.p12/.pfx) file.
/// Certificates asserting BasicConstraints cA are skipped; an absent extension counts as a leaf.
pub fn extract_leaf_certificate_from_p12(data: &[u8], password: &str) -> Result<Vec<u8>, P12Error> {
    for contents in open_safe_contents(data, password)? {
        let bags = asn1::parse_single::<asn1::SequenceOf<SafeBag>>(&contents)
            .map_err(|e| P12Error::Other(format!("SafeContents decode: {}", e)))?;
        for bag in bags {
            let BagValue::CertBag(cert_bag) = bag.bag_value else { continue };
            let CertType::X509(cert) = cert_bag.into_inner().cert_value else { continue };
            let der = cert.into_inner().into_inner().full_data();
            let cert = asn1::parse_single::<Certificate>(der).map_err(|e| P12Error::Other(format!("certificate parse: {}", e)))?;
            let extensions = cert.extensions().map_err(|e| P12Error::Other(format!("duplicate certificate extension: {}", e.0)))?;
            let is_ca = match extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
                Some(ext) => ext.value::<BasicConstraints>().map_err(|e| P12Error::Other(format!("BasicConstraints parse: {}", e)))?.ca,
                None => false,
            };
            if !is_ca {
                return Ok(der.to_vec());
            }
        }
    }
    Err(P12Error::NoLeafCertificate)
}

fn find_key_in_safe_contents(der: &[u8], password: &str) -> Result<Option<Vec<u8>>, P12Error> {
    let bags = asn1::parse_single::<asn1::SequenceOf<SafeBag>>(der).map_err(|e| P12Error::Other(format!("SafeContents decode: {}", e)))?;
    for bag in bags {
        match bag.bag_value {
            BagValue::ShroudedKeyBag(epki) => {
                let epki = epki.as_inner();
                let decrypted = pbes2_decrypt(&epki.encryption_algorithm, password, epki.encrypted_data)?;
                return Ok(Some(decrypted));
            }
            BagValue::KeyBag(key) => return Ok(Some(key.as_inner().full_data().to_vec())),
            BagValue::CertBag(_) | BagValue::Other(..) => {}
        }
    }
    Ok(None)
}

fn pbes2_decrypt(alg: &AlgorithmIdentifier, password: &str, ciphertext: &[u8]) -> Result<Vec<u8>, P12Error> {
    use aes::{Aes128, Aes192, Aes256};
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

    let pbes2 = match &alg.params {
        AlgorithmParameters::Pbes2(p) => p,
        _ => return Err(P12Error::Other(format!("Unsupported PBE scheme: {} (only PBES2 supported)", alg.oid()))),
    };

    let pbkdf2 = match &pbes2.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(p) => p,
        _ => return Err(P12Error::Other(format!("Unsupported PBES2 KDF: {} (only PBKDF2 supported)", pbes2.key_derivation_func.oid()))),
    };

    let enc = &pbes2.encryption_scheme;
    let (key_len, iv): (usize, &[u8]) = match &enc.params {
        AlgorithmParameters::Aes128Cbc(iv) => (16, iv),
        AlgorithmParameters::Aes192Cbc(iv) => (24, iv),
        AlgorithmParameters::Aes256Cbc(iv) => (32, iv),
        #[cfg(feature = "decrypt-3des")]
        AlgorithmParameters::DesEde3Cbc(iv) => (24, iv),
        _ => return Err(P12Error::Other(format!("Unsupported PBES2 cipher: {}", enc.oid()))),
    };

    if pbkdf2.salt.len() < 8 {
        return Err(P12Error::Other(format!("PBKDF2 salt length {} is below minimum of 8 bytes", pbkdf2.salt.len())));
    }
    if pbkdf2.iteration_count > 100_000_000 {
        return Err(P12Error::Other(format!("PBKDF2 iteration count {} is unreasonably high", pbkdf2.iteration_count)));
    }
    if pbkdf2.iteration_count < 100_000 {
        eprintln!("Warning: PBKDF2 iteration count {} is below recommended minimum of 100000", pbkdf2.iteration_count);
    }

    // RFC 8018 paragraph A.2: dispatch on the PRF (default is hmacWithSHA1)
    let rounds = pbkdf2.iteration_count as u32;
    let mut key = vec![0u8; key_len];
    match &pbkdf2.prf.params {
        AlgorithmParameters::HmacWithSha1(_) => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha224(_) => return Err(P12Error::Other("PBKDF2 with HMAC-SHA-224 not supported".to_owned())),
        AlgorithmParameters::HmacWithSha256(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha384(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        AlgorithmParameters::HmacWithSha512(_) => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), pbkdf2.salt, rounds, &mut key),
        _ => return Err(P12Error::Other(format!("Unsupported PBKDF2 PRF: {}", pbkdf2.prf.oid()))),
    };

    let mut buf = ciphertext.to_vec();
    // A padding failure after decryption almost always means the key was derived
    // from the wrong password, so classify it as WrongPassword.
    macro_rules! do_decrypt {
        ($cipher:ty) => {
            cbc::Decryptor::<$cipher>::new_from_slices(&key, iv)
                .map_err(|e| P12Error::Other(format!("cipher init: {}", e)))?
                .decrypt_padded::<Pkcs7>(&mut buf)
                .map_err(|e| P12Error::WrongPassword(format!("cipher decrypt: {}", e)))?
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
fn verify_pfx_mac(mac_data: &MacData, auth_safe_bytes: &[u8], password: &str) -> Result<(), P12Error> {
    use pbkdf2::hmac::{Hmac, Mac, digest::KeyInit};

    let salt = mac_data.salt;
    if salt.len() < 8 {
        return Err(P12Error::Other(format!("PKCS#12 MAC salt length {} is below minimum of 8 bytes", salt.len())));
    }
    let iterations = mac_data.iterations;
    if iterations == 0 {
        return Err(P12Error::Other("PKCS#12 MAC iteration count 0 is invalid".to_owned()));
    }
    if iterations > 100_000_000 {
        return Err(P12Error::Other(format!("PKCS#12 MAC iteration count {} is unreasonably high", iterations)));
    }
    let rounds = iterations as i32;
    let expected_mac = mac_data.mac.digest;

    // RFC 7292 Appendix B: derive MAC key using PKCS#12 KDF with id=3 (Mac).
    // An empty password has two encodings in the wild: an empty BMPString (just the
    // two-byte NUL terminator) or a zero-length string (NULL password). Like OpenSSL,
    // accept either when no password was supplied.
    macro_rules! verify_mac {
        ($hash:ty, $mac_len:expr) => {{
            let verify = |mac_key: &[u8]| -> Result<(), P12Error> {
                let mut mac = Hmac::<$hash>::new_from_slice(mac_key).map_err(|e| P12Error::Other(format!("HMAC init: {}", e)))?;
                mac.update(auth_safe_bytes);
                mac.verify_slice(expected_mac)
                    .map_err(|_| P12Error::WrongPassword("PKCS#12 MAC verification failed (wrong password or corrupted file)".to_string()))
            };
            let bmp_key = pkcs12::kdf::derive_key_utf8::<$hash>(password, salt, pkcs12::kdf::Pkcs12KeyType::Mac, rounds, $mac_len)
                .map_err(|e| P12Error::Other(format!("MAC key derivation: {}", e)))?;
            match verify(&bmp_key) {
                Err(P12Error::WrongPassword(_)) if password.is_empty() => {
                    verify(&pkcs12::kdf::derive_key::<$hash>(&[], salt, pkcs12::kdf::Pkcs12KeyType::Mac, rounds, $mac_len))
                }
                result => result,
            }
        }};
    }

    match &mac_data.mac.algorithm.params {
        AlgorithmParameters::Sha1(_) => verify_mac!(sha1::Sha1, 20),
        AlgorithmParameters::Sha256(_) => verify_mac!(sha2::Sha256, 32),
        AlgorithmParameters::Sha384(_) => verify_mac!(sha2::Sha384, 48),
        AlgorithmParameters::Sha512(_) => verify_mac!(sha2::Sha512, 64),
        _ => Err(P12Error::Other(format!("Unsupported MAC digest algorithm: {}", mac_data.mac.algorithm.oid()))),
    }
}
