// Validation of externally-generated messages, the CVE-2018-18509 proof-of-concept.

use smime::errors::SmimeError;
use smime::{TrustStore, verify_smime_from_eml_detailed};
use std::fs;

#[test]
fn test_e_content_confusion() {
    let file_path = "tests/cve-2018-18509/eContentConfusion.eml";
    let eml = fs::read_to_string(file_path).expect("Failed to read file");
    let result = verify_smime_from_eml_detailed(eml, vec![TrustStore::Debug].into());
    println!("Result for {}: {:#?}", file_path, result);
    result.signed_content.as_ref().expect("Signed content should be present");
    assert!(result.failures.iter().any(|f| matches!(f, SmimeError::DigestVerify { err } if err.contains("digests not equivalent"))));
}
