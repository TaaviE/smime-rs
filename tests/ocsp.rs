// Stapled-OCSP revocation-signal tests. Fixtures come from `create-cms ocsp`:
// a root CA that issued a valid leaf, with an OCSP staple in SignedData.crls.
use smime::ocsp::StapledStatus;
use smime::{TrustConfig, verify_smime_from_eml_detailed};

// Trust anchor for the fixtures: the self-signed "Test Stapling Root CA" that issued
// the leaves (key: tests/keys/test_rsa_sign), written by `create-cms ocsp`.
const ROOT_CA_PEM: &str = include_str!("ocsp/root_ca.pem");

fn verify_fixture(name: &str) -> smime::SmimeValidationResult {
    let eml = std::fs::read_to_string(format!("tests/ocsp/{name}.eml")).expect("read fixture");
    let trust = TrustConfig { stores: vec![], ca_file_pem: Some(ROOT_CA_PEM.as_bytes().to_vec()) };
    verify_smime_from_eml_detailed(eml, trust)
}

#[test]
fn issuer_signed_good_is_recorded() {
    let result = verify_fixture("stapled_issuer_good");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Good));
}

#[test]
fn sha256_certid_good_is_recorded() {
    // RFC 6960 lets the CertID use any hash; a SHA-256 CertID must be matched, not ignored.
    let result = verify_fixture("stapled_issuer_good_sha256_certid");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Good));
}

#[test]
fn delegated_responder_good_is_recorded() {
    let result = verify_fixture("stapled_responder_good");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Good));
}

#[test]
fn revoked_staple_invalidates_unexpired_cert() {
    // The leaf has not expired, but a valid stapled OCSP says revoked.
    let result = verify_fixture("stapled_issuer_revoked");
    let signer = result.signers.first().expect("one signer");
    assert!(!signer.validation_details.certificate_trusted_valid, "revoked cert must be invalid even though unexpired");
    assert!(!signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Revoked));
}

#[test]
fn expired_responder_staple_is_ignored() {
    // A Good response signed by a delegated responder whose certificate has expired must
    // be ignored: the responder is not valid at verification time, so the leaf stays
    // trusted but carries no stapled-OCSP status.
    let result = verify_fixture("stapled_responder_expired");
    assert!(result.failures.is_empty(), "an expired-responder staple must not raise validation errors: {:?}", result.failures);
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none(), "expired responder's response must not be recorded as good");
}

#[test]
fn forged_good_is_ignored() {
    // A Good OCSP with a correct CertID, signed with the attacker's key while claiming
    // to be the root, must not be recorded: an attacker must not be able to mint a Good
    // badge for a certificate the issuer never vouched for.
    let result = verify_fixture("stapled_forged_issuer");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none(), "forged good staple must not be recorded as good");
}

#[test]
fn forged_revocation_is_ignored() {
    // A Revoked OCSP with a correct CertID, signed with the attacker's key while claiming
    // to be the root, must not invalidate the certificate: the signature is verified against
    // the trust-anchored issuer's key, so the forged signature is rejected.
    let result = verify_fixture("stapled_forged_revoked");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid, "forged revocation must not invalidate a valid cert");
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none());
}

#[test]
fn certid_mismatch_revocation_is_ignored() {
    // A Revoked OCSP validly signed by the real root, but whose CertID identifies a
    // different issuer key, must not invalidate the certificate: it does not match this
    // leaf/issuer pair and is discarded at certID matching, before the signature is checked.
    let result = verify_fixture("stapled_certid_mismatch_revoked");
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid, "non-matching certID must not invalidate a valid cert");
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none());
}

#[test]
fn stale_good_staple_is_ignored() {
    // A Good staple whose nextUpdate is long past must not be accepted as a current
    // revocation signal (RFC 6960 3.2). The stale response is ignored: the leaf stays
    // trusted but carries no stapled-OCSP status.
    let result = verify_fixture("stapled_good_stale_response");
    assert!(result.failures.is_empty(), "a stale staple must not raise validation errors: {:?}", result.failures);
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none(), "stale OCSP response must not be recorded as good");
}

#[test]
fn good_staple_without_next_update_expires_after_cap() {
    // A Good staple with no nextUpdate is honored for at most 7 days after thisUpdate.
    // This one's thisUpdate is years old, so the cap expires it: it is ignored (no status),
    // the leaf stays trusted, and no validation error is raised.
    let result = verify_fixture("stapled_good_no_next_update");
    assert!(result.failures.is_empty(), "an expired nextUpdate-less staple must not raise errors: {:?}", result.failures);
    let signer = result.signers.first().expect("one signer");
    assert!(signer.validation_details.certificate_trusted_valid);
    assert!(signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none(), "a stale nextUpdate-less staple must not be recorded as good");
}

#[test]
fn expired_cert_with_good_staple_is_untrusted() {
    let result = verify_fixture("expired_leaf_good_staple");
    let signer = result.signers.first().expect("one signer");
    assert!(!signer.validation_details.certificate_trusted_valid);
    assert!(!signer.signature_valid);
    assert!(signer.validation_details.revocation_status.is_none());
}

#[test]
fn revoked_intermediate_invalidates_chain() {
    // Three-level chain root -> intermediate -> leaf where the leaf staples Good but the
    // intermediate staples Revoked: the revocation must be promoted over the leaf's own
    // Good status and the error must name the intermediate, not the leaf.
    let result = verify_fixture("stapled_intermediate_revoked");
    let signer = result.signers.first().expect("one signer");
    assert!(!signer.validation_details.certificate_trusted_valid, "revoked intermediate must invalidate the chain");
    assert!(!signer.signature_valid);
    assert_eq!(signer.validation_details.revocation_status, Some(StapledStatus::Revoked));
    assert!(
        result.failures.iter().any(
            |f| matches!(f, smime::errors::SmimeError::StapledOcspRevoked { subject } if subject.contains("Test Stapling Intermediate CA"))
        ),
        "the revocation error must name the intermediate: {:?}",
        result.failures
    );
}
