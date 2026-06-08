#![cfg(feature = "decrypt")]

#[cfg(test)]
mod tests {
    use smime::errors::SmimeError;

    #[test]
    fn test_wrong_content_type_rejected() {
        use smime::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters, Asn1ReadableOrWritable};
        use smime::cryptography_x509::pkcs7::*;

        let iv: [u8; 16] = [0u8; 16];
        let dummy_ct = [0u8; 16];
        let wrong_oid = PKCS7_SIGNED_DATA_OID;

        let enveloped = EnvelopedData {
            version: 0,
            originator_info: None,
            recipient_infos: Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&[])),
            encrypted_content_info: EncryptedContentInfo {
                content_type: wrong_oid,
                content_encryption_algorithm: AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: AlgorithmParameters::Aes128Cbc(iv),
                },
                encrypted_content: Some(&dummy_ct),
            },
            unprotected_attrs: None,
        };

        let der = asn1::write_single(&enveloped).unwrap();
        let parsed: EnvelopedData = asn1::parse_single(&der).unwrap();
        let dummy_key = [0u8; 32];
        let err = smime::decrypt::decrypt_enveloped_data(
            &parsed,
            &smime::decrypt::DecryptionKeys { private_key_der: &dummy_key, ..Default::default() },
        )
        .unwrap_err();
        assert!(
            matches!(err, SmimeError::UnsupportedContentEncryptionAlg { ref alg } if alg.contains("contentType")),
            "expected contentType error, got: {:?}",
            err,
        );
    }
}
