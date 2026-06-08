use actix_web::{App, HttpResponse, HttpServer, Responder, ResponseError, middleware::Logger, post, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

// TODO: Move into utils
fn asn1_to_chrono(dt: &asn1::DateTime) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::Utc
        .with_ymd_and_hms(dt.year() as i32, dt.month() as u32, dt.day() as u32, dt.hour() as u32, dt.minute() as u32, dt.second() as u32)
        .single()
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: String,
}

use chrono::TimeZone;
use smime::cryptography_x509::certificate::Certificate;
use smime::cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters, Asn1Read, Asn1ReadableOrWritable};
use smime::cryptography_x509::crl::CertificateRevocationList;
use smime::cryptography_x509::extensions::{AuthorityKeyIdentifier, Extension, Extensions};
use smime::cryptography_x509::name::Name;
use smime::cryptography_x509::ocsp_req::{CertID, OCSPRequest, Request, TBSRequest};
use smime::cryptography_x509::ocsp_resp::{BasicOCSPResponse, CertStatus, OCSPResponse, ResponderId, Response, SingleResponse};
use smime::cryptography_x509::oid;

use smime::cryptography_x509_verification::ops::CryptoOps;
use smime::types::KeyCryptoOps;

#[derive(Debug)]
enum ProxyError {
    BadRequest(String),
    ResponseError(String),
    ResponseViolation(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::BadRequest(s) => write!(f, "Bad request: {}", s),
            ProxyError::ResponseError(s) => write!(f, "Proxy error: {}", s),
            ProxyError::ResponseViolation(s) => write!(f, "Signature error: {}", s),
        }
    }
}

impl ResponseError for ProxyError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ProxyError::BadRequest(s) => HttpResponse::BadRequest().body(s.clone()),
            ProxyError::ResponseError(s) => HttpResponse::InternalServerError().body(s.clone()),
            ProxyError::ResponseViolation(s) => HttpResponse::Unauthorized().body(s.clone()),
        }
    }
}

type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Deserialize, Serialize)]
struct OcspRequestPayload {
    certificate: String,
    issuer: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct OcspResponsePayload {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    produced_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    this_update: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_update: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct CrlRequestPayload {
    certificate: String,
    issuer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CrlResponsePayload {
    revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_date: Option<String>,
}

fn decode_cert(data: &str) -> ProxyResult<Vec<u8>> {
    if let Ok(p) = pem::parse(data) {
        return Ok(p.into_contents());
    }
    BASE64.decode(data.trim()).map_err(|_| ProxyError::BadRequest("Failed to decode certificate: not valid PEM or base64".to_string()))
}

fn names_match(a: &Name<'_>, b: &Name<'_>) -> ProxyResult<bool> {
    let a_der = asn1::write_single(a).map_err(|_| ProxyError::ResponseError("Failed to encode name".to_string()))?;
    let b_der = asn1::write_single(b).map_err(|_| ProxyError::ResponseError("Failed to encode name".to_string()))?;
    Ok(a_der == b_der)
}

fn get_ski<'a>(cert: &'a Certificate<'a>) -> Option<&'a [u8]> {
    cert.extensions().ok()?.get_extension(&oid::SUBJECT_KEY_IDENTIFIER_OID).and_then(|ext| ext.value::<&[u8]>().ok())
}

fn get_aki_key_identifier<'a>(cert: &'a Certificate<'a>) -> Option<Vec<u8>> {
    cert.extensions()
        .ok()?
        .get_extension(&oid::AUTHORITY_KEY_IDENTIFIER_OID)
        .and_then(|ext| ext.value::<AuthorityKeyIdentifier<'_, Asn1Read>>().ok())
        .and_then(|aki| aki.key_identifier.map(|k| k.to_vec()))
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn check_aki_matches_issuer(child: &Certificate<'_>, issuer: &Certificate<'_>) -> ProxyResult<()> {
    let Some(aki_key_id) = get_aki_key_identifier(child) else {
        return Ok(());
    };
    let issuer_id =
        get_ski(issuer).map(|s| s.to_vec()).unwrap_or_else(|| sha1_of(issuer.tbs_cert.spki.subject_public_key.as_bytes()).to_vec());
    if aki_key_id != issuer_id {
        return Err(ProxyError::ResponseViolation("Authority Key Identifier does not match issuer's Subject Key Identifier".to_string()));
    }
    Ok(())
}

fn require_ca_cert(cert: &Certificate<'_>) -> ProxyResult<()> {
    let is_ca = cert
        .extensions()
        .ok()
        .and_then(|exts| exts.get_extension(&oid::BASIC_CONSTRAINTS_OID))
        .and_then(|ext| ext.value::<smime::cryptography_x509::extensions::BasicConstraints>().ok())
        .is_some_and(|bc| bc.ca);
    if !is_ca {
        return Err(ProxyError::BadRequest("Certificate must be a CA certificate (basicConstraints CA:TRUE)".to_string()));
    }
    Ok(())
}

fn verify_cert_issued_by(cert: &Certificate<'_>, issuer: &Certificate<'_>) -> ProxyResult<()> {
    if !names_match(&cert.tbs_cert.issuer, &issuer.tbs_cert.subject)? {
        return Err(ProxyError::BadRequest("Certificate issuer DN does not match supplied issuer's subject DN".to_string()));
    }
    check_aki_matches_issuer(cert, issuer)?;

    let ops = KeyCryptoOps {};
    let issuer_key = ops.public_key(issuer).map_err(|e| ProxyError::BadRequest(format!("Failed to extract issuer public key: {}", e)))?;
    ops.verify_signed_by(cert, &issuer_key)
        .map_err(|e| ProxyError::BadRequest(format!("Certificate was not signed by the provided issuer: {}", e)))
}

fn validate_fetch_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("Invalid URL '{}': {}", raw, e))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("Disallowed URL scheme '{}' in '{}'", s, raw)),
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() || ip.is_private() || ip.is_link_local() => {
            Err(format!("URL '{}' points to a private/internal address", raw))
        }
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Err(format!("URL '{}' points to a loopback address", raw)),
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => Err(format!("URL '{}' points to localhost", raw)),
        None => Err(format!("URL '{}' has no host", raw)),
        _ => Ok(()),
    }
}

fn get_ocsp_url(cert: &Certificate<'_>) -> Option<String> {
    let extensions = cert.extensions().ok()?;
    let ext = extensions.get_extension(&oid::AUTHORITY_INFORMATION_ACCESS_OID)?;
    let aia = ext.value::<asn1::SequenceOf<'_, smime::cryptography_x509::extensions::AccessDescription<'_>>>().ok()?;

    for ad in aia {
        if ad.access_method == oid::OCSP_OID {
            if let smime::cryptography_x509::name::GeneralName::UniformResourceIdentifier(uri) = ad.access_location {
                return Some(uri.0.to_string());
            }
        }
    }
    None
}

fn get_crl_urls(cert: &Certificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    let extensions = match cert.extensions() {
        Ok(e) => e,
        Err(_) => return urls,
    };

    let ext = match extensions.get_extension(&oid::CRL_DISTRIBUTION_POINTS_OID) {
        Some(e) => e,
        None => return urls,
    };

    let dps = match ext.value::<asn1::SequenceOf<
        '_,
        smime::cryptography_x509::extensions::DistributionPoint<
            '_,
            smime::cryptography_x509::common::Asn1Read,
        >,
    >>() {
        Ok(d) => d,
        Err(_) => return urls,
    };

    for dp in dps {
        if let Some(smime::cryptography_x509::extensions::DistributionPointName::FullName(names)) = dp.distribution_point {
            for name in names {
                if let smime::cryptography_x509::name::GeneralName::UniformResourceIdentifier(uri) = name {
                    urls.push(uri.0.to_string());
                }
            }
        }
    }
    urls
}

#[post("/ocsp")]
async fn check_ocsp(payload: web::Json<OcspRequestPayload>, client: web::Data<reqwest::Client>) -> ProxyResult<impl Responder> {
    let cert_der = decode_cert(&payload.certificate)?;
    let issuer_der = decode_cert(&payload.issuer)?;

    let cert = asn1::parse_single::<Certificate<'_>>(&cert_der).map_err(|_| ProxyError::BadRequest("Invalid certificate".to_string()))?;

    let issuer =
        asn1::parse_single::<Certificate<'_>>(&issuer_der).map_err(|_| ProxyError::BadRequest("Invalid issuer certificate".to_string()))?;

    require_ca_cert(&cert)?;
    verify_cert_issued_by(&cert, &issuer)?;

    let ocsp_url = get_ocsp_url(&cert).ok_or_else(|| ProxyError::BadRequest("No OCSP URL in certificate".to_string()))?;
    validate_fetch_url(&ocsp_url).map_err(ProxyError::BadRequest)?;

    let (req_der, req_nonce, expected_name_hash, expected_key_hash) = create_ocsp_request(&cert, &issuer, false)?;

    let resp = client
        .post(&ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(req_der)
        .send()
        .await
        .map_err(|e| ProxyError::ResponseError(format!("OCSP request failed: {}", e)))?;

    let resp_bytes = resp.bytes().await.map_err(|e| ProxyError::ResponseError(format!("Failed to read OCSP response: {}", e)))?;

    let ocsp_resp = asn1::parse_single::<OCSPResponse<'_>>(&resp_bytes)
        .map_err(|e| ProxyError::ResponseError(format!("Failed to parse OCSP ASN.1 response: {:?}", e)))?;

    match ocsp_resp.response_status.value() {
        0 => {}
        1 => {
            return Err(ProxyError::ResponseError("OCSP responder error: Malformed request".to_string()));
        }
        2 => return Err(ProxyError::ResponseError("OCSP responder error: Internal error".to_string())),
        3 => return Err(ProxyError::ResponseError("OCSP responder error: Try again later".to_string())),
        4 => return Err(ProxyError::ResponseError("OCSP responder error: Unused/Invalid".to_string())),
        5 => return Err(ProxyError::ResponseError("OCSP responder error: Sig required".to_string())),
        6 => return Err(ProxyError::ResponseError("OCSP responder error: Unauthorized".to_string())),
        status => return Err(ProxyError::ResponseError(format!("OCSP responder error: Unknown: {}", status))),
    }

    match ocsp_resp.response_bytes {
        Some(bytes) => {
            let basic_resp = match bytes.response {
                Response::Basic(r) => r,
            }
            .into_inner();

            match verify_ocsp_signature(&basic_resp, &issuer) {
                Err(e) => return Err(e),
                Ok(_) => {}
            };

            if !req_nonce.is_empty() {
                let resp_nonce = basic_resp
                    .tbs_response_data
                    .raw_response_extensions
                    .as_ref()
                    .and_then(|extensions| extensions.unwrap_read().clone().find(|ext| ext.extn_id == oid::NONCE_OID))
                    .and_then(|ext| ext.value::<&[u8]>().ok());

                if let Some(resp_nonce) = resp_nonce {
                    if req_nonce.as_slice() != resp_nonce {
                        return Err(ProxyError::ResponseViolation("OCSP nonce mismatch".to_string()));
                    }
                } else {
                    log::warn!("OCSP nonce missing");
                }
            }

            match basic_resp.tbs_response_data.responses.unwrap_read().clone().next() {
                Some(single_resp) => {
                    if *single_resp.cert_id.hash_algorithm.oid() != oid::SHA1_OID
                        || single_resp.cert_id.issuer_name_hash != expected_name_hash
                        || single_resp.cert_id.issuer_key_hash != expected_key_hash
                        || single_resp.cert_id.serial_number != cert.tbs_cert.serial
                    {
                        return Err(ProxyError::ResponseViolation("OCSP response certID does not match request".to_string()));
                    }

                    // 4.9.10 On‑line revocation checking requirements
                    if let Some(ref next_update) = single_resp.next_update {
                        let this_update_dt = single_resp.this_update.as_datetime();
                        let next_update_dt: asn1::DateTime = next_update.as_datetime().to_owned();

                        let this_chrono = asn1_to_chrono(&this_update_dt)
                            .ok_or_else(|| ProxyError::ResponseViolation("Invalid thisUpdate date".to_string()))?;

                        let next_chrono = asn1_to_chrono(&next_update_dt)
                            .ok_or_else(|| ProxyError::ResponseViolation("Invalid nextUpdate date".to_string()))?;

                        let duration = next_chrono.signed_duration_since(this_chrono);

                        let is_subscriber_cert = !cert
                            .tbs_cert
                            .extensions()
                            .map_err(|_| ProxyError::ResponseViolation("Invalid certificate extensions".to_string()))?
                            .get_extension(&oid::BASIC_CONSTRAINTS_OID)
                            .and_then(|ext| ext.value::<smime::cryptography_x509::extensions::BasicConstraints>().ok())
                            .map(|bc| bc.ca)
                            .unwrap_or(false);

                        if is_subscriber_cert {
                            // 4.9.10: 1. OCSP responses SHALL have a validity interval greater than or equal to eight hours;
                            if duration < chrono::Duration::hours(8) {
                                return Err(ProxyError::ResponseViolation("OCSP validity interval less than 8 hours".to_string()));
                            }
                            // 4.9.10: 2. OCSP responses SHALL have a validity interval less than or equal to ten days;
                            if duration > chrono::Duration::days(10) {
                                return Err(ProxyError::ResponseViolation("OCSP validity interval greater than 10 days".to_string()));
                            }
                        } else {
                            // For Subordinate CA Certificates current absolute maximum can be 12 months
                            if duration > chrono::Duration::days(256) {
                                return Err(ProxyError::ResponseViolation("OCSP validity interval greater than 12 months".to_string()));
                            }
                        }

                        let now = chrono::Utc::now();
                        if now < this_chrono {
                            return Err(ProxyError::ResponseViolation("OCSP response thisUpdate is in the future".to_string()));
                        }
                        if now > next_chrono {
                            return Err(ProxyError::ResponseViolation("OCSP response has expired (past nextUpdate)".to_string()));
                        }
                    }

                    Ok(HttpResponse::Ok().json(OcspResponsePayload {
                        status: get_cert_status_str(&single_resp).to_string(),
                        produced_at: Some(format!("{:?}", &basic_resp.tbs_response_data.produced_at.as_datetime())),
                        this_update: Some(format!("{:?}", &single_resp.this_update.as_datetime())),
                        next_update: single_resp.next_update.map(|t| format!("{:?}", &t.as_datetime())),
                    }))
                }
                None => Err(ProxyError::ResponseError("Empty OCSP response".to_string())),
            }
        }
        None => Err(ProxyError::ResponseError("Empty or invalid OCSP response".to_string())),
    }
}

fn check_algorithm_permitted(alg: &AlgorithmIdentifier<'_>) -> ProxyResult<()> {
    if !smime::cryptography_x509_verification::policy::SMIME_PERMITTED_SIGNATURE_ALGORITHMS.contains(alg) {
        return Err(ProxyError::ResponseViolation(format!("Disallowed signature algorithm: {:?}", alg.oid())));
    }
    Ok(())
}

fn verify_ocsp_signature(basic_resp: &BasicOCSPResponse<'_>, issuer: &Certificate<'_>) -> ProxyResult<()> {
    let ops = KeyCryptoOps {};

    let tbs_der = asn1::write_single(&basic_resp.tbs_response_data)
        .map_err(|_| ProxyError::ResponseError("Failed to encode OCSP TBS response data".to_string()))?;

    check_algorithm_permitted(&basic_resp.signature_algorithm)?;

    let issuer_spki_hash = sha1_of(issuer.tbs_cert.spki.subject_public_key.as_bytes());
    let issuer_matches_responder_id = match &basic_resp.tbs_response_data.responder_id {
        ResponderId::ByName(name) => names_match(name, &issuer.tbs_cert.subject)?,
        ResponderId::ByKey(hash) => *hash == issuer_spki_hash.as_slice(),
    };

    let issuer_pubkey =
        ops.public_key(issuer).map_err(|e| ProxyError::ResponseError(format!("Failed to extract issuer public key: {}", e)))?;

    if issuer_matches_responder_id {
        if smime::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm(
            &issuer_pubkey,
            &basic_resp.signature_algorithm,
            basic_resp.signature.as_bytes(),
            &tbs_der,
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    if let Some(certs) = &basic_resp.certs {
        for cert in certs.unwrap_read().clone() {
            let candidate_matches = match &basic_resp.tbs_response_data.responder_id {
                ResponderId::ByName(name) => names_match(name, &cert.tbs_cert.subject)?,
                ResponderId::ByKey(hash) => *hash == sha1_of(cert.tbs_cert.spki.subject_public_key.as_bytes()).as_slice(),
            };
            if !candidate_matches {
                continue;
            }

            if !names_match(&cert.tbs_cert.issuer, &issuer.tbs_cert.subject)? {
                continue;
            }
            if check_aki_matches_issuer(&cert, issuer).is_err() {
                continue;
            }

            if check_algorithm_permitted(&cert.signature_alg).is_err() {
                continue;
            }
            let cert_tbs_der = asn1::write_single(&cert.tbs_cert)
                .map_err(|_| ProxyError::ResponseError("Failed to encode responder TBS cert".to_string()))?;
            if smime::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm(
                &issuer_pubkey,
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &cert_tbs_der,
            )
            .is_err()
            {
                continue;
            }

            let extensions = match cert.extensions() {
                Ok(e) => e,
                Err(_) => continue,
            };

            let has_ocsp_signing = extensions
                .get_extension(&oid::EXTENDED_KEY_USAGE_OID)
                .and_then(|ext| ext.value::<asn1::SequenceOf<'_, asn1::ObjectIdentifier>>().ok())
                .map(|ekus| ekus.into_iter().any(|eku| eku == oid::EKU_OCSP_SIGNING_OID))
                .unwrap_or(false);

            let has_no_check = extensions.get_extension(&oid::OCSP_NO_CHECK_OID).is_some();

            if !(has_ocsp_signing && has_no_check) {
                continue;
            }

            let now = chrono::Utc::now();
            let not_before = asn1_to_chrono(&cert.tbs_cert.validity.not_before.as_datetime());
            let not_after = asn1_to_chrono(&cert.tbs_cert.validity.not_after.as_datetime());
            if let (Some(nb), Some(na)) = (not_before, not_after) {
                if now < nb || now > na {
                    continue;
                }
            }

            let responder_pubkey = match ops.public_key(&cert) {
                Ok(k) => k,
                Err(_) => continue,
            };

            if smime::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm(
                &responder_pubkey,
                &basic_resp.signature_algorithm,
                basic_resp.signature.as_bytes(),
                &tbs_der,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }

    Err(ProxyError::ResponseViolation("OCSP signature verification failed (neither issuer nor authorized responder)".to_string()))
}

fn create_ocsp_request(
    cert: &Certificate<'_>,
    issuer: &Certificate<'_>,
    nonce: bool,
) -> ProxyResult<(Vec<u8>, Vec<u8>, [u8; 20], [u8; 20])> {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    let issuer_name_der =
        asn1::write_single(&cert.tbs_cert.issuer).map_err(|_| ProxyError::ResponseError("Failed to encode issuer name".to_string()))?;

    hasher.update(&issuer_name_der);
    let issuer_name_hash: [u8; 20] = hasher.finalize_reset().into();

    hasher.update(issuer.tbs_cert.spki.subject_public_key.as_bytes());
    let issuer_key_hash: [u8; 20] = hasher.finalize().into();

    let cert_id = CertID {
        hash_algorithm: AlgorithmIdentifier { oid: asn1::DefinedByMarker::marker(), params: AlgorithmParameters::Sha1(Some(())) },
        issuer_name_hash: &issuer_name_hash,
        issuer_key_hash: &issuer_key_hash,
        serial_number: cert.tbs_cert.serial,
    };

    let requests = [Request { req_cert: cert_id, single_request_extensions: None }];

    if nonce {
        let mut nonce_bytes = [0u8; 16];
        getrandom::fill(&mut nonce_bytes).map_err(|_| ProxyError::ResponseError("Failed to generate random nonce".to_string()))?;
        let nonce_der =
            asn1::write_single(&nonce_bytes.as_slice()).map_err(|_| ProxyError::ResponseError("Failed to encode nonce".to_string()))?;

        let ocsp_req = OCSPRequest {
            tbs_request: TBSRequest {
                version: 0,
                requestor_name: None,
                request_list: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&requests)),
                raw_request_extensions: Some(Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(vec![Extension {
                    extn_id: oid::NONCE_OID,
                    critical: false,
                    extn_value: &nonce_der,
                }]))),
            },
            optional_signature: None,
        };

        let req_der = asn1::write_single(&ocsp_req).map_err(|_| ProxyError::ResponseError("Failed to encode OCSP request".to_string()))?;
        return Ok((req_der, nonce_bytes.to_vec(), issuer_name_hash, issuer_key_hash));
    }

    let ocsp_req = OCSPRequest {
        tbs_request: TBSRequest {
            version: 0,
            requestor_name: None,
            request_list: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&requests)),
            raw_request_extensions: None,
        },
        optional_signature: None,
    };

    let req_der = asn1::write_single(&ocsp_req).map_err(|_| ProxyError::ResponseError("Failed to encode OCSP request".to_string()))?;
    Ok((req_der, Vec::new(), issuer_name_hash, issuer_key_hash))
}

fn get_cert_status_str(single_resp: &SingleResponse<'_>) -> &'static str {
    match single_resp.cert_status {
        CertStatus::Good(_) => "good",
        CertStatus::Revoked(_) => "revoked",
        CertStatus::Unknown(_) => "unknown",
    }
}

#[post("/crl")]
async fn check_crl(payload: web::Json<CrlRequestPayload>, client: web::Data<reqwest::Client>) -> ProxyResult<impl Responder> {
    let cert_der = decode_cert(&payload.certificate)?;
    let cert = asn1::parse_single::<Certificate<'_>>(&cert_der).map_err(|_| ProxyError::BadRequest("Invalid certificate".to_string()))?;

    let issuer_der = payload.issuer.as_ref().map(|i| decode_cert(i)).transpose()?;
    let issuer_cert = if let Some(der) = &issuer_der {
        Some(asn1::parse_single::<Certificate<'_>>(der).map_err(|_| ProxyError::BadRequest("Invalid issuer certificate".to_string()))?)
    } else {
        None
    };

    let issuer =
        issuer_cert.as_ref().ok_or_else(|| ProxyError::BadRequest("Issuer certificate is required to verify CRL signature".to_string()))?;

    require_ca_cert(&cert)?;
    verify_cert_issued_by(&cert, issuer)?;

    let crl_urls = get_crl_urls(&cert);
    if crl_urls.is_empty() {
        return Err(ProxyError::BadRequest("No CRL Distribution Points in certificate".to_string()));
    }

    for url in &crl_urls {
        if let Err(e) = validate_fetch_url(url) {
            log::warn!("Skipping invalid CRL URL: {}", e);
            continue;
        }
        let resp = match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let crl_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        let crl = match asn1::parse_single::<CertificateRevocationList<'_>>(&crl_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };

        verify_crl_signature(&crl, issuer)?;

        // 4.9.7 CRL issuance
        if let Some(next_update) = &crl.tbs_cert_list.next_update {
            let this_update_dt = crl.tbs_cert_list.this_update.as_datetime();
            let next_update_dt = next_update.as_datetime();

            let this_chrono =
                asn1_to_chrono(&this_update_dt).ok_or_else(|| ProxyError::ResponseError("Invalid CRL thisUpdate date".to_string()))?;

            let next_chrono =
                asn1_to_chrono(&next_update_dt).ok_or_else(|| ProxyError::ResponseError("Invalid CRL nextUpdate date".to_string()))?;

            let duration = next_chrono.signed_duration_since(this_chrono);

            let is_subscriber_cert = !cert
                .tbs_cert
                .extensions()
                .map_err(|_| ProxyError::BadRequest("Invalid certificate extensions".to_string()))?
                .get_extension(&oid::BASIC_CONSTRAINTS_OID)
                .and_then(|ext| ext.value::<smime::cryptography_x509::extensions::BasicConstraints>().ok())
                .map(|bc| bc.ca)
                .unwrap_or(false);

            if is_subscriber_cert {
                // For Subscriber Certificates: nextUpdate SHALL NOT be more than ten days beyond thisUpdate
                if duration > chrono::Duration::days(10) {
                    return Err(ProxyError::ResponseViolation(
                        "CRL validity interval greater than 10 days for subscriber cert".to_string(),
                    ));
                }
            } else {
                // For Subordinate CA Certificates: nextUpdate SHALL NOT be more than twelve months beyond thisUpdate
                if duration > chrono::Duration::days(366) {
                    return Err(ProxyError::ResponseViolation("CRL validity interval greater than 12 months for CA cert".to_string()));
                }
            }

            let now = chrono::Utc::now();
            if now < this_chrono {
                return Err(ProxyError::ResponseViolation("CRL thisUpdate is in the future".to_string()));
            }
            if now > next_chrono {
                return Err(ProxyError::ResponseViolation("CRL has expired (past nextUpdate)".to_string()));
            }
        }

        if let Some(revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            let mut iter = revoked_certs.unwrap_read().clone();
            while let Some(revoked) = iter.next() {
                if revoked.user_certificate == cert.tbs_cert.serial {
                    return Ok(HttpResponse::Ok().json(CrlResponsePayload {
                        revoked: true,
                        reason: None,
                        revocation_date: Some(format!("{:?}", revoked.revocation_date.as_datetime())),
                    }));
                }
            }
        }

        return Ok(HttpResponse::Ok().json(CrlResponsePayload { revoked: false, reason: None, revocation_date: None }));
    }

    Err(ProxyError::ResponseError("Failed to fetch or parse any CRL".to_string()))
}

fn verify_crl_signature(crl: &CertificateRevocationList<'_>, issuer: &Certificate<'_>) -> ProxyResult<()> {
    if !names_match(&crl.tbs_cert_list.issuer, &issuer.tbs_cert.subject)? {
        return Err(ProxyError::ResponseViolation("CRL issuer DN does not match supplied issuer's subject DN".to_string()));
    }

    let crl_extensions = Extensions::from_raw_extensions(crl.tbs_cert_list.raw_crl_extensions.as_ref())
        .map_err(|_| ProxyError::ResponseError("Duplicate CRL extensions".to_string()))?;
    if let Some(aki_ext) = crl_extensions.get_extension(&oid::AUTHORITY_KEY_IDENTIFIER_OID) {
        let aki = aki_ext
            .value::<AuthorityKeyIdentifier<'_, Asn1Read>>()
            .map_err(|e| ProxyError::ResponseError(format!("Failed to parse CRL AuthorityKeyIdentifier: {}", e)))?;
        if let Some(crl_aki) = aki.key_identifier {
            let issuer_id =
                get_ski(issuer).map(|s| s.to_vec()).unwrap_or_else(|| sha1_of(issuer.tbs_cert.spki.subject_public_key.as_bytes()).to_vec());
            if crl_aki != issuer_id.as_slice() {
                return Err(ProxyError::ResponseViolation(
                    "CRL Authority Key Identifier does not match issuer's Subject Key Identifier".to_string(),
                ));
            }
        }
    }

    if let Ok(extensions) = issuer.extensions() {
        if let Some(ext) = extensions.get_extension(&oid::KEY_USAGE_OID) {
            let ku = ext
                .value::<smime::cryptography_x509::extensions::KeyUsage<'_>>()
                .map_err(|e| ProxyError::ResponseError(format!("Failed to parse KeyUsage: {}", e)))?;
            if !ku.crl_sign() {
                return Err(ProxyError::ResponseViolation("Issuer certificate does not have CRL Sign key usage".to_string()));
            }
        }
    }

    let ops = KeyCryptoOps {};
    let issuer_pubkey =
        ops.public_key(issuer).map_err(|e| ProxyError::ResponseError(format!("Failed to extract issuer public key: {}", e)))?;

    let tbs_der =
        asn1::write_single(&crl.tbs_cert_list).map_err(|_| ProxyError::ResponseError("Failed to encode CRL TBS cert list".to_string()))?;

    check_algorithm_permitted(&crl.signature_algorithm)?;
    smime::cryptography_x509_verify::sign::verify_signature_with_signature_algorithm(
        &issuer_pubkey,
        &crl.signature_algorithm,
        crl.signature_value.as_bytes(),
        &tbs_der,
    )
    .map_err(|e| ProxyError::ResponseViolation(format!("CRL signature verification failed: {}", e)))?;

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    log::info!("Starting validation proxy on {}", cli.bind);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");
    HttpServer::new(move || {
        App::new().app_data(web::Data::new(client.clone())).wrap(Logger::default()).service(check_ocsp).service(check_crl)
    })
    .bind(&cli.bind)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test, web};
    use std::fs;

    #[actix_rt::test]
    async fn test_ocsp_route() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/DigiCert Assured G2 SMIME RSA4096 SHA384 2024 CA1.pem")
            .expect("Failed to read certificate file");
        let issuer_pem =
            fs::read_to_string("tests/validation-proxy/DigiCert Assured ID Root G2.pem").expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_ocsp)).await;

        let payload = OcspRequestPayload { certificate: cert_pem, issuer: issuer_pem };

        let req = test::TestRequest::post().uri("/ocsp").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        if !resp.status().is_success() {
            let body = test::read_body(resp).await;
            panic!("Request failed: {:?}", String::from_utf8_lossy(&body));
        }

        let body: OcspResponsePayload = test::read_body_json(resp).await;
        assert_eq!(body.status, "good");
    }

    #[actix_rt::test]
    async fn test_crl_route() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/DigiCert Assured G2 SMIME RSA4096 SHA384 2024 CA1.pem")
            .expect("Failed to read certificate file");
        let issuer_pem =
            fs::read_to_string("tests/validation-proxy/DigiCert Assured ID Root G2.pem").expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_crl)).await;

        let payload = CrlRequestPayload { certificate: cert_pem, issuer: Some(issuer_pem) };

        let req = test::TestRequest::post().uri("/crl").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        if !resp.status().is_success() {
            let body = test::read_body(resp).await;
            panic!("Request failed: {:?}", String::from_utf8_lossy(&body));
        }

        let body: CrlResponsePayload = test::read_body_json(resp).await;
        assert!(!body.revoked);
    }

    #[actix_rt::test]
    async fn test_ocsp_rejects_leaf_cert() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/Aruba PEC Signer.pem").expect("Failed to read certificate file");
        let issuer_pem = fs::read_to_string("tests/validation-proxy/AgID CA1.pem").expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_ocsp)).await;

        let payload = OcspRequestPayload { certificate: cert_pem, issuer: issuer_pem };
        let req = test::TestRequest::post().uri("/ocsp").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_crl_rejects_leaf_cert() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/Aruba PEC Signer.pem").expect("Failed to read certificate file");
        let issuer_pem = fs::read_to_string("tests/validation-proxy/AgID CA1.pem").expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_crl)).await;

        let payload = CrlRequestPayload { certificate: cert_pem, issuer: Some(issuer_pem) };
        let req = test::TestRequest::post().uri("/crl").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_ocsp_route_agid_ca() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/AgID CA1.pem").expect("Failed to read certificate file");
        let issuer_pem = fs::read_to_string("tests/validation-proxy/Actalis Authentication Root CA.pem")
            .expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_ocsp)).await;

        let payload = OcspRequestPayload { certificate: cert_pem, issuer: issuer_pem };
        let req = test::TestRequest::post().uri("/ocsp").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        if !resp.status().is_success() {
            let body = test::read_body(resp).await;
            panic!("Request failed: {:?}", String::from_utf8_lossy(&body));
        }

        let body: OcspResponsePayload = test::read_body_json(resp).await;
        assert!(body.status == "good" || body.status == "unknown" || body.status == "revoked");
    }

    #[actix_rt::test]
    async fn test_crl_route_agid_ca() {
        let cert_pem = fs::read_to_string("tests/validation-proxy/AgID CA1.pem").expect("Failed to read certificate file");
        let issuer_pem = fs::read_to_string("tests/validation-proxy/Actalis Authentication Root CA.pem")
            .expect("Failed to read issuer certificate file");

        let client = reqwest::Client::new();
        let app = test::init_service(App::new().app_data(web::Data::new(client.clone())).service(check_crl)).await;

        let payload = CrlRequestPayload { certificate: cert_pem, issuer: Some(issuer_pem) };
        let req = test::TestRequest::post().uri("/crl").set_json(&payload).to_request();

        let resp = test::call_service(&app, req).await;
        if !resp.status().is_success() {
            let body = test::read_body(resp).await;
            panic!("Request failed: {:?}", String::from_utf8_lossy(&body));
        }

        let body: CrlResponsePayload = test::read_body_json(resp).await;
        assert!(!body.revoked);
    }
}
