// OCSP-in-CMS interop with OpenSSL
// Tests generated OCSP against OSSL and vice versa, just to be more certain

use smime::ocsp::StapledStatus;
use smime::{TrustConfig, verify_smime_from_eml_detailed};
use std::path::PathBuf;
use std::process::Command;

// Same trust anchor as tests/ocsp.rs: the "Test Stapling Root CA" written by `create-cms ocsp`.
const ROOT_CA_PEM: &str = include_str!("ocsp/root_ca.pem");

fn verify_fixture(name: &str) -> smime::SmimeValidationResult {
    let eml = std::fs::read_to_string(format!("tests/ocsp/{name}.eml")).expect("read fixture");
    let trust = TrustConfig { stores: vec![], ca_file_pem: Some(ROOT_CA_PEM.as_bytes().to_vec()) };
    verify_smime_from_eml_detailed(eml, trust)
}

// Producer side: the OCSP responses in these fixtures are signed by `openssl ocsp`, not by our
// own build_ocsp_response, so they cross-check our validator against OpenSSL's encoding.

#[test]
fn openssl_issuer_good_is_recorded() {
    let result = verify_fixture("openssl_issuer_good");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Good));
}

#[test]
fn openssl_issuer_revoked_invalidates_cert() {
    let result = verify_fixture("openssl_issuer_revoked");
    let signer = result.signers.first().expect("one signer");
    assert!(!signer.validation_details.certificate_trusted_valid, "OpenSSL revoked staple must invalidate the cert");
    assert!(!signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Revoked));
}

#[test]
fn openssl_delegated_responder_good_is_recorded() {
    let result = verify_fixture("openssl_responder_good");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Good));
}

fn openssl_available() -> bool {
    Command::new("openssl").arg("version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn root_ca_file() -> PathBuf {
    let path = std::env::temp_dir().join("rust_smime_ocsp_interop_root.pem");
    std::fs::write(&path, ROOT_CA_PEM).unwrap();
    path
}

// The fixtures here are produced by our own create-cms (Rust), consumed by OpenSSL.
const FIXTURE: &str = "tests/ocsp/stapled_issuer_good.eml";

#[test]
fn openssl_verifies_our_stapled_signeddata() {
    if !openssl_available() {
        eprintln!("skipping: openssl not on PATH");
        return;
    }
    let root = root_ca_file();
    let out = Command::new("openssl")
        .args(["cms", "-verify", "-in", FIXTURE, "-CAfile"])
        .arg(&root)
        .args(["-out", "/dev/null"])
        .output()
        .expect("run openssl cms -verify");
    assert!(out.status.success(), "openssl could not verify our OCSP-stapled SignedData: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn openssl_parses_our_stapled_ocsp_revinfo() {
    if !openssl_available() {
        eprintln!("skipping: openssl not on PATH");
        return;
    }
    let out =
        Command::new("openssl").args(["cms", "-cmsout", "-in", FIXTURE, "-print", "-noout"]).output().expect("run openssl cms -cmsout");
    assert!(out.status.success(), "openssl cms -cmsout failed: {}", String::from_utf8_lossy(&out.stderr));
    let printed = String::from_utf8_lossy(&out.stdout);
    // RFC 5940 id-ri-ocsp-response embedded in SignedData.crls as otherRevInfo.
    assert!(printed.contains("1.3.6.1.5.5.7.16.2"), "OpenSSL did not show the OCSP otherRevInfo OID:\n{printed}");
    assert!(printed.contains("Basic OCSP Response"), "OpenSSL did not parse the embedded Basic OCSP Response:\n{printed}");
}
