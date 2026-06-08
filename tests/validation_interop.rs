#[cfg(test)]
mod tests {
    use smime::errors::SmimeError;
    use smime::{TrustStore, verify_smime_from_eml_detailed};
    use std::fs;

    #[test]
    fn test_pkcs7_mime_opaque() {
        let eml = fs::read_to_string("tests/general/pkcs7-mime.eml").expect("Failed to read eml file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result: {:#?}", result);
    }

    #[test]
    fn test_valid_eml() {
        let eml = fs::read_to_string("tmp/valid.eml").expect("Failed to read tmp/valid.eml");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Builtin].into());
        println!("Result: {:#?}", result);
        assert!(!result.signers.is_empty(), "expected at least one signer");
        assert!(result.failures.is_empty(), "unexpected failures: {:?}", result.failures);
        assert!(result.signers[0].signature_valid);
    }

    #[test]
    fn test_date_delta_warning() {
        let mut eml = fs::read_to_string("tests/header-protection/smime-multipart-hp.eml").unwrap();

        eml = eml.replacen("Date: Sat, 20 Feb 2021 10:07:02 -0500", "Date: Sat, 20 Feb 2021 18:07:02 -0500", 1);

        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        let notes = &result.signers[0].validation_details.other_notes;
        println!("Result: {:#?}", result);

        assert!(notes.iter().any(|n| matches!(n, SmimeError::DateMismatch { msg, .. } if msg.contains("The time difference between the outer date and the inner date is larger than one hour"))));
        assert!(notes.iter().any(|n| matches!(n, SmimeError::DateMismatch { msg, .. } if msg.contains("The time difference between the signing time and outer date header is larger than one hour"))));
    }

    #[test]
    fn test_e_content_confusion() {
        let file_path = "tests/cve-2018-18509/eContentConfusion.eml";
        let eml = fs::read_to_string(file_path).expect("Failed to read file");
        let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
        println!("Result for {}: {:#?}", file_path, result);
        result.signed_content.as_ref().expect("Signed content should be present");
        assert!(result.failures.iter().any(|f| matches!(f, SmimeError::DigestVerify { err } if err.contains("digests not equivalent"))));
    }
}
