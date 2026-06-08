#![cfg(feature = "decrypt")]

#[cfg(test)]
mod tests {
    use aes::{Aes128, Aes192, Aes256};
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    use smime::decrypt::decrypt_aes_cbc;
    use smime::errors::SmimeError;

    fn encrypt_aes_cbc(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let padded_len = (plaintext.len() / block_size + 1) * block_size;
        let mut buf = vec![0u8; padded_len];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        macro_rules! do_encrypt {
            ($cipher:ty) => {
                cbc::Encryptor::<$cipher>::new_from_slices(key, iv)
                    .unwrap()
                    .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
                    .unwrap()
                    .to_vec()
            };
        }
        match key.len() {
            16 => do_encrypt!(Aes128),
            24 => do_encrypt!(Aes192),
            32 => do_encrypt!(Aes256),
            _ => panic!("bad key len"),
        }
    }

    fn random_bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| ((i as u8).wrapping_mul(0x6D)).wrapping_add(seed)).collect()
    }

    fn random_array<const N: usize>(seed: u8) -> [u8; N] {
        let v = random_bytes(N, seed);
        v.try_into().unwrap()
    }

    #[test]
    fn aes_128_cbc_roundtrip() {
        let key = random_array::<16>(0x31);
        let iv = random_array::<16>(0x72);
        let pt = b"Hello, AES-128-CBC!";
        let ct = encrypt_aes_cbc(&key, &iv, pt);
        assert_eq!(decrypt_aes_cbc(&key, 16, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn aes_192_cbc_roundtrip() {
        let key = random_array::<24>(0xA3);
        let iv = random_array::<16>(0xB4);
        let pt = b"Hello, AES-192-CBC!";
        let ct = encrypt_aes_cbc(&key, &iv, pt);
        assert_eq!(decrypt_aes_cbc(&key, 24, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn aes_256_cbc_roundtrip() {
        let key = random_array::<32>(0xC5);
        let iv = random_array::<16>(0xD6);
        let pt = b"Hello, AES-256-CBC!";
        let ct = encrypt_aes_cbc(&key, &iv, pt);
        assert_eq!(decrypt_aes_cbc(&key, 32, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn aes_cbc_bad_padding() {
        let key = random_array::<16>(0xE7);
        let iv = random_array::<16>(0xF8);
        let bad_ct = random_bytes(16, 0x99);
        assert!(decrypt_aes_cbc(&key, 16, &iv, &bad_ct).is_err());
    }

    #[test]
    fn aes_cbc_invalid_key_length() {
        let key = random_bytes(15, 0x1A);
        let iv = random_array::<16>(0x2B);
        let ct = random_bytes(16, 0x3C);
        let err = decrypt_aes_cbc(&key, 15, &iv, &ct).unwrap_err();
        assert!(matches!(err, SmimeError::DecryptionFailed { ref err } if err.contains("15 bytes")));
    }

    #[test]
    fn aes_cbc_empty_plaintext() {
        let key = random_array::<16>(0x4D);
        let iv = random_array::<16>(0x5E);
        let ct = encrypt_aes_cbc(&key, &iv, b"");
        assert!(decrypt_aes_cbc(&key, 16, &iv, &ct).unwrap().is_empty());
    }

    #[test]
    fn aes_128_cbc_nist_vector() {
        // NIST SP 800-38A F.2.1 CBC-AES128.Decrypt
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let ciphertext = hex::decode(
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7",
        )
        .unwrap();
        let expected_plaintext = hex::decode(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        )
        .unwrap();
        use cbc::cipher::BlockModeDecrypt;
        let mut buf = ciphertext.clone();
        let decryptor = cbc::Decryptor::<Aes128>::new_from_slices(&key, &iv).unwrap();
        let pt = decryptor.decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf).unwrap();
        assert_eq!(pt, expected_plaintext.as_slice());
    }

    #[test]
    fn aes_256_cbc_nist_vector() {
        // NIST SP 800-38A F.2.5 CBC-AES256.Decrypt
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let ciphertext = hex::decode(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
             9cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461\
             b2eb05e2c39be9fcda6c19078c6a9d1b",
        )
        .unwrap();
        let expected_plaintext = hex::decode(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        )
        .unwrap();
        use cbc::cipher::BlockModeDecrypt;
        let mut buf = ciphertext.clone();
        let decryptor = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv).unwrap();
        let pt = decryptor.decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf).unwrap();
        assert_eq!(pt, expected_plaintext.as_slice());
    }

    #[cfg(feature = "decrypt-3des")]
    #[test]
    fn pwri_3des_rfc3211_vector2() {
        // RFC 3211 §4 Test Vector 2: 3DES PWRI key wrap with PBKDF2 (HMAC-SHA1)
        // Password: "All n-entities must communicate with other n-entities via n-1 entiteeheehees"
        // Salt: 1234567878563412, iterations: 500
        // KEK (PBKDF2 output): 6A8970BF68C92CAEA84A8DF28510858607126380CC47AB2D
        // CEK (unwrapped): 8C637D887223A2F965B566EB014B0FA5D52300A3F7EA40FFFC577203C71BAF3B
        use smime::cryptography_x509::pkcs7::RecipientInfo;

        // DER-encoded PasswordRecipientInfo ([3] IMPLICIT), reconstructed from RFC 3211 §4
        let pwri_der = hex::decode(
            "a36f\
             020100\
             a01b\
               06092a864886f70d01050c\
               300e\
                 04081234567878563412\
                 020201f4\
             3023\
               060b2a864886f70d0109100309\
               3014\
                 06082a864886f70d0307\
                 0408baf1ca7931213c4e\
             0428\
               c03c514abdb9e2c5aac038572b5e2455\
               3876b377aafb82eca5a9d73f8ab143d9\
               ec74e6cad7db260c",
        )
        .unwrap();
        let ri: RecipientInfo = asn1::parse_single(&pwri_der).unwrap();
        let pwri = match ri {
            RecipientInfo::PasswordRecipientInfo(p) => p,
            _ => panic!("expected PasswordRecipientInfo"),
        };
        let password = "All n-entities must communicate with other n-entities via n-1 entiteeheehees";
        let (cek, _warnings) = smime::decrypt::decrypt_pwri_cek(Some(password), &pwri).unwrap();
        assert_eq!(hex::encode(&cek), "8c637d887223a2f965b566eb014b0fa5d52300a3f7ea40fffc577203c71baf3b");
    }

    #[test]
    fn pbkdf2_hmac_sha1_rfc6070() {
        let mut dk = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 1, &mut dk);
        assert_eq!(hex::encode(dk), "0c60c80f961f0e71f3a9b524af6012062fe037a6");

        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 2, &mut dk);
        assert_eq!(hex::encode(dk), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 4096, &mut dk);
        assert_eq!(hex::encode(dk), "4b007901b765489abead49d926f721d065a429c1");
    }

    #[test]
    fn pkcs12_kdf_sha256() {
        use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};

        let key =
            derive_key_utf8::<sha2::Sha256>("ge@\u{00e4}heim", &[1, 2, 3, 4, 5, 6, 7, 8], Pkcs12KeyType::EncryptionKey, 100, 32).unwrap();
        assert_eq!(hex::encode(&key), "fae4d4957a3cc781e1180b9d4fb79c1e0c8579b746a3177e5b0768a3118bf863");

        let iv = derive_key_utf8::<sha2::Sha256>("ge@\u{00e4}heim", &[1, 2, 3, 4, 5, 6, 7, 8], Pkcs12KeyType::Iv, 100, 32).unwrap();
        assert_eq!(hex::encode(&iv), "e5ff813bc6547de5155b14d2fada85b3201a977349db6e26ccc998d9e8f83d6c");

        let mac = derive_key_utf8::<sha2::Sha256>("ge@\u{00e4}heim", &[1, 2, 3, 4, 5, 6, 7, 8], Pkcs12KeyType::Mac, 100, 32).unwrap();
        assert_eq!(hex::encode(&mac), "136355ed9434516682534f46d63956db5ff06b844702c2c1f3b46321e2524a4d");
    }

    #[test]
    fn pkcs12_kdf_sha512() {
        use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};

        let key =
            derive_key_utf8::<sha2::Sha512>("ge@\u{00e4}heim", &[1, 2, 3, 4, 5, 6, 7, 8], Pkcs12KeyType::EncryptionKey, 100, 32).unwrap();
        assert_eq!(hex::encode(&key), "b14a9f01bfd9dce4c9d66d2fe9937e5fd9f1afa59e370a6fa4fc81c1cc8ec8ee");
    }

    // RFC 3211 §2.3.1 CEK formatting test vectors
    #[test]
    fn rfc3211_cek_format_vector1() {
        let cek = hex::decode("8C627C89732323A2F8").unwrap();
        // format: length || ~cek[0] || ~cek[1] || ~cek[2] || cek || padding
        assert_eq!(cek.len() as u8, 0x09);
        assert_eq!(!cek[0], 0x73);
        assert_eq!(!cek[1], 0x9D);
        assert_eq!(!cek[2], 0x83);
    }

    #[test]
    fn rfc3211_cek_format_vector2() {
        let cek = hex::decode("8C637D887223A2F965B566EB014B0FA5D52300A3F7EA40FFFC577203C71BAF3B").unwrap();
        assert_eq!(cek.len(), 32);
        assert_eq!(cek[0], 0x8C);
        assert_eq!(!cek[0], 0x73);
        assert_eq!(!cek[1], 0x9C);
        assert_eq!(!cek[2], 0x82);
    }

    // RFC 3211 §3 PBKDF2 test vectors
    #[test]
    fn rfc3211_pbkdf2_vector1() {
        let salt = hex::decode("1234567878563412").unwrap();
        let mut key = vec![0u8; 8];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", &salt, 5, &mut key);
        assert_eq!(hex::encode(&key), "d1daa78615f287e6");
    }

    #[test]
    fn rfc3211_pbkdf2_vector2() {
        let passphrase = b"All n-entities must communicate with other n-entities via n-1 entiteeheehees";
        let salt = hex::decode("1234567878563412").unwrap();
        let mut key = vec![0u8; 24];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &salt, 500, &mut key);
        assert_eq!(hex::encode(&key), "6a8970bf68c92caea84a8df28510858607126380cc47ab2d");
    }

    // RFC 3211 wrap/unwrap roundtrip using AES-256-CBC.
    // Wraps with raw CBC (matching OpenSSL cms_pwri.c:295-296), unwraps via decrypt_pwri_cek.
    #[test]
    fn rfc3211_aes256_wrap_unwrap_roundtrip() {
        use smime::cryptography_x509::common::*;
        use smime::cryptography_x509::pkcs7::PasswordRecipientInfo;

        let password = "test-password";
        let cek: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let salt: [u8; 16] = [0xAA; 16];
        let iterations: u32 = 1000;
        let mut kek = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, iterations, &mut kek);

        // RFC 3211 §2.3.1: format + double-encrypt
        let bs: usize = 16;
        let padded_len = ((4 + cek.len() + bs - 1) / bs).max(2) * bs;
        let mut wrapped = vec![0u8; padded_len];
        wrapped[0] = cek.len() as u8;
        wrapped[1] = !cek[0];
        wrapped[2] = !cek[1];
        wrapped[3] = !cek[2];
        wrapped[4..36].copy_from_slice(&cek);
        let wrap_iv: [u8; 16] = [0xBB; 16];
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let enc = aes::Aes256Enc::new_from_slice(&kek).unwrap();
        let mut enc_iv = wrap_iv;
        for _pass in 0..2 {
            for i in 0..padded_len / bs {
                let start = i * bs;
                for j in 0..bs {
                    wrapped[start + j] ^= enc_iv[j];
                }
                let mut block = aes::cipher::Array::from(<[u8; 16]>::try_from(&wrapped[start..start + bs]).unwrap());
                enc.encrypt_block(&mut block);
                wrapped[start..start + bs].copy_from_slice(&block);
                enc_iv.copy_from_slice(&wrapped[start..start + bs]);
            }
        }

        // Build PWRI ASN.1 and unwrap via library
        let inner_alg = AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Aes256Cbc(wrap_iv) };
        let inner_alg_der = asn1::write_single(&inner_alg).unwrap();
        let inner_alg_tlv: asn1::Tlv = asn1::parse_single(&inner_alg_der).unwrap();
        let pwri = PasswordRecipientInfo {
            version: 0,
            key_derivation_algorithm: Some(AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Pbkdf2(PBKDF2Params {
                    salt: &salt,
                    iteration_count: iterations as u64,
                    key_length: Some(32),
                    prf: Box::new(AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: AlgorithmParameters::HmacWithSha256(Some(())),
                    }),
                }),
            }),
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Other(asn1::oid!(1, 2, 840, 113549, 1, 9, 16, 3, 9), Some(inner_alg_tlv)),
            },
            encrypted_key: &wrapped,
        };
        let pwri_der = asn1::write_single(&pwri).unwrap();
        let parsed: PasswordRecipientInfo = asn1::parse_single(&pwri_der).unwrap();

        let (recovered, _) = smime::decrypt::decrypt_pwri_cek(Some(password), &parsed).expect("PWRI unwrap failed");
        assert_eq!(recovered, cek);
    }

    // RFC 9709 Appendix B test vectors
    #[test]
    fn rfc9709_cek_hkdf_sha256_aes128_gcm() {
        let ikm = hex::decode("c702e7d0a9e064b09ba55245fb733cf3").unwrap();
        let info = hex::decode("301b0609608648016503040106300e040c5c79058ba2f43447639d29e2").unwrap();
        let expected = hex::decode("2124ffb29fac4e0fbbc7d5d87492bff3").unwrap();
        let okm = smime::decrypt::cms_cek_hkdf_sha256(&ikm, &info).unwrap();
        assert_eq!(okm, expected);
    }

    #[test]
    fn rfc9709_cek_hkdf_sha256_aes128_cbc() {
        let ikm = hex::decode("c702e7d0a9e064b09ba55245fb733cf3").unwrap();
        let info = hex::decode("301d06096086480165030401020410651f722ffd512c52fe072e507d72b377").unwrap();
        let expected = hex::decode("9cd102c52f1e19ece8729b35bfeceb50").unwrap();
        let okm = smime::decrypt::cms_cek_hkdf_sha256(&ikm, &info).unwrap();
        assert_eq!(okm, expected);
    }
}
