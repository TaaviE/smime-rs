use base64::prelude::*;
use clap::{Parser, Subcommand};
use mail_parser::{HeaderName, MessageParser, MimeHeaders};
use smime::cryptography_x509::certificate::Certificate;
use smime::cryptography_x509::certificate::Certificate as PyCertificate;
use smime::cryptography_x509::common::{AlgorithmParameters, Asn1ReadableOrWritable, Time};
use smime::cryptography_x509::crl::CertificateRevocationList;
use smime::cryptography_x509::ocsp_req::{CertID, OCSPRequest, Request, TBSRequest};
use smime::cryptography_x509::oid as x509_oid;

use smime::cryptography_x509::oid::OCSP_OID;
use smime::cryptography_x509::pkcs7::{
    CertificateChoices, Content, ContentInfo, OtherRevocationInfoFormat, RevocationInfoChoice, SignerInfo,
};
use smime::cryptography_x509_verification::ops::CryptoOps;
use smime::types::KeyCryptoOps;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Modify a CMS/PKCS#7 message (add certs, CRLs, OCSP responses)
    Modify(ModifyArgs),
    /// Rewrite PKCS#7 content in an .eml file from BER to DER encoding
    BerToDer(BerToDerArgs),
}

#[derive(Parser, Debug)]
struct ModifyArgs {
    /// Path to the input .eml file
    #[arg(short, long, default_value = "tmp/galileo.eml")]
    eml: PathBuf,

    /// Path to the intermediate certificate PEM file
    #[arg(short, long, default_value = "tmp/Sectigo Public Email Protection CA R36.pem")]
    cert: PathBuf,

    /// Path to the output modified .eml file
    #[arg(short, long, default_value = "tmp/galileo_modified.eml")]
    output: PathBuf,

    /// Path to an additional certificate to add to the CMS (optional)
    #[arg(long)]
    cert_path: Option<PathBuf>,

    /// Path to the CRL file (optional, will fetch if not provided)
    #[arg(long)]
    crl_path: Option<PathBuf>,

    /// Path to the OCSP response file (optional, will fetch if not provided)
    #[arg(long)]
    ocsp_path: Option<PathBuf>,

    /// Add an OCSP response (from --ocsp-path, or fetched if not provided)
    #[arg(long, default_value = "false")]
    ocsp: bool,
}

#[derive(Parser, Debug)]
struct BerToDerArgs {
    /// Path to the input .eml file
    #[arg(short, long)]
    eml: PathBuf,

    /// Path to the output .eml file
    #[arg(short, long)]
    output: PathBuf,
}

fn get_cn_from_name(name: &smime::cryptography_x509::name::NameReadable<'_>) -> Option<String> {
    use smime::cryptography_x509::common::AttributeValue;
    for rdn in name.clone() {
        for attr in rdn {
            if attr.type_id == x509_oid::COMMON_NAME_OID {
                return match &attr.value {
                    AttributeValue::PrintableString(s) => Some(s.as_str().to_string()),
                    AttributeValue::AnyString(tlv) => {
                        if matches!(tlv.tag(), t if t == asn1::Tag::primitive(12) || t == asn1::Tag::primitive(22)) {
                            std::str::from_utf8(tlv.data()).ok().map(|s| s.to_string())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
            }
        }
    }
    None
}

fn is_pkcs7_content_type(part: &mail_parser::MessagePart) -> bool {
    part.content_type().is_some_and(|ct| {
        ct.c_type.as_ref().eq_ignore_ascii_case("application")
            && ct.c_subtype.as_ref().is_some_and(|subtype| {
                subtype.eq_ignore_ascii_case("pkcs7-mime")
                    || subtype.eq_ignore_ascii_case("x-pkcs7-mime")
                    || subtype.eq_ignore_ascii_case("pkcs7-signature")
                    || subtype.eq_ignore_ascii_case("x-pkcs7-signature")
            })
    })
}

// Only the scheme is restricted so this experimental test utility stays usable in test environments.
fn validate_fetch_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("Invalid URL '{}': {}", raw, e))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        s => Err(format!("Disallowed URL scheme '{}' in '{}'", s, raw)),
    }
}

fn get_crl_urls(cert: &PyCertificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    let extensions = match cert.extensions() {
        Ok(e) => e,
        Err(_) => return urls,
    };

    let ext = match extensions.get_extension(&x509_oid::CRL_DISTRIBUTION_POINTS_OID) {
        Some(e) => e,
        None => return urls,
    };

    let dps = match ext.value::<asn1::SequenceOf<
        '_,
        smime::cryptography_x509::extensions::DistributionPoint<'_, smime::cryptography_x509::common::Asn1Read>,
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

fn get_ocsp_urls(cert: &PyCertificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    let extensions = match cert.extensions() {
        Ok(e) => e,
        Err(_) => return urls,
    };

    let ext = match extensions.get_extension(&x509_oid::AUTHORITY_INFORMATION_ACCESS_OID) {
        Some(e) => e,
        None => return urls,
    };

    let ads = match ext.value::<asn1::SequenceOf<'_, smime::cryptography_x509::extensions::AccessDescription<'_>>>() {
        Ok(d) => d,
        Err(_) => return urls,
    };

    for ad in ads {
        if ad.access_method == OCSP_OID {
            if let smime::cryptography_x509::name::GeneralName::UniformResourceIdentifier(uri) = ad.access_location {
                urls.push(uri.0.to_string());
            }
        }
    }
    urls
}

fn ber_to_der(args: BerToDerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let eml_bytes = fs::read(&args.eml).map_err(|e| format!("Failed to read EML file {:?}: {}", args.eml, e))?;
    let message = MessageParser::default().parse(&eml_bytes).ok_or("Failed to parse EML")?;

    let mut result = eml_bytes.clone();
    // Process parts in reverse order so earlier offsets remain valid after splicing
    let mut pkcs7_parts: Vec<_> = message.parts.iter().filter(|p| is_pkcs7_content_type(p)).collect();
    pkcs7_parts.sort_by(|a, b| b.offset_body.cmp(&a.offset_body));

    if pkcs7_parts.is_empty() {
        return Err("No PKCS#7 MIME parts found in message".into());
    }

    for part in &pkcs7_parts {
        let body_start = part.offset_body as usize;
        let body_end = part.offset_end as usize;

        let decoded = part.contents().to_vec();
        let der = smime::utils::ber_to_der_cms(&decoded).map_err(|e| format!("BER-to-DER: {}", e))?;

        let b64 = BASE64_STANDARD.encode(&der);
        let mut wrapped = String::new();
        for (i, chunk) in b64.as_bytes().chunks(76).enumerate() {
            if i > 0 {
                wrapped.push_str("\r\n");
            }
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
        }
        wrapped.push_str("\r\n");

        result = [&result[..body_start], wrapped.as_bytes(), &result[body_end..]].concat();
        println!("Converted PKCS#7 part at offset {}..{}", body_start, body_end);
    }

    fs::write(&args.output, &result)?;
    println!("BER-to-DER rewritten EML written to {:?}", args.output);
    Ok(())
}

fn run_modify(args: ModifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let eml_content = fs::read(&args.eml).map_err(|e| format!("Failed to read EML file {:?}: {}", args.eml, e))?;
    let message = MessageParser::default().parse(&eml_content).ok_or("Failed to parse EML")?;

    let p7m_part = if message.parts.is_empty() {
        None
    } else {
        message.parts.iter().find(|part| {
            part.content_type().is_some_and(|ct| {
                ct.c_type.as_ref().eq_ignore_ascii_case("application")
                    && ct
                        .c_subtype
                        .as_ref()
                        .is_some_and(|subtype| subtype.eq_ignore_ascii_case("pkcs7-mime") || subtype.eq_ignore_ascii_case("x-pkcs7-mime"))
            })
        })
    };

    let p7m_contents = if let Some(part) = p7m_part {
        part.contents().to_vec()
    } else if !message.parts.is_empty() {
        return Err("No PKCS#7 MIME part found in message".into());
    } else {
        message.body_html(0).or(message.body_text(0)).map(|b| b.as_bytes().to_vec()).ok_or("No PKCS#7 MIME part found in message")?
    };

    let p7m_der = smime::utils::ber_to_der_cms(&p7m_contents).map_err(|e| format!("BER-to-DER: {}", e))?;
    let content_info = asn1::parse_single::<ContentInfo>(&p7m_der).map_err(|e| format!("Failed to parse PKCS#7 message: {:?}", e))?;

    let mut signed_data = match content_info.content {
        Content::SignedData(sd) => sd.into_inner(),
        _ => return Err("Not a SignedData PKCS#7 message".into()),
    };

    // Build filtered headers from the original message
    let allowed_headers = |name: &HeaderName| {
        matches!(
            name,
            HeaderName::From
                | HeaderName::To
                | HeaderName::Subject
                | HeaderName::Date
                | HeaderName::ContentType
                | HeaderName::ContentDisposition
                | HeaderName::ContentTransferEncoding
                | HeaderName::MimeVersion
        )
    };

    let root_part = p7m_part.unwrap_or(&message.parts[0]);
    let mut headers_bytes = Vec::new();
    let mut has_date = false;
    for header in &root_part.headers {
        if allowed_headers(&header.name) {
            if matches!(header.name, HeaderName::Date) {
                has_date = true;
            }
            let raw = &eml_content[header.offset_field as usize..header.offset_end as usize];
            headers_bytes.extend_from_slice(raw);
        }
    }

    // If no Date header, extract signing time from CMS SignerInfo
    if !has_date {
        let signers: Vec<SignerInfo<'_>> = signed_data.signer_infos.unwrap_read().clone().collect();
        let mut signing_time = None;
        if let Some(signer) = signers.first() {
            if let Some(attrs) = signer.authenticated_attributes.as_ref() {
                for attr in attrs.unwrap_read().clone() {
                    if attr.type_id == x509_oid::SIGNING_TIME_OID {
                        let mut values = attr.values.unwrap_read().clone().collect::<Vec<_>>();
                        if values.len() == 1 {
                            if let Ok(time) = asn1::parse_single::<Time>(values.remove(0).full_data()) {
                                let dt = time.as_datetime();
                                signing_time = Some(format!(
                                    "Date: {}\r\n",
                                    chrono::NaiveDate::from_ymd_opt(dt.year() as i32, dt.month() as u32, dt.day() as u32)
                                        .and_then(|d| d.and_hms_opt(dt.hour() as u32, dt.minute() as u32, dt.second() as u32))
                                        .map(|ndt| ndt.and_utc().format("%a, %d %b %Y %H:%M:%S +0000").to_string())
                                        .unwrap_or_default()
                                ));
                            }
                        }
                    }
                }
            }
        }
        if let Some(date_header) = signing_time {
            headers_bytes.extend_from_slice(date_header.as_bytes());
        }
    }

    // Blank line separating headers from body
    headers_bytes.extend_from_slice(b"\r\n");

    let cert_pem = fs::read_to_string(&args.cert).map_err(|e| format!("Failed to read certificate file {:?}: {}", args.cert, e))?;
    let pem = pem::parse(cert_pem)?;
    let cert_der = pem.contents().to_vec();
    let intermediate_cert =
        asn1::parse_single::<PyCertificate<'_>>(&cert_der).map_err(|e| format!("Failed to decode intermediate certificate: {:?}", e))?;

    let mut certs: Vec<CertificateChoices<'_>> =
        signed_data.certificates.as_ref().map(|c| c.unwrap_read().clone().collect()).unwrap_or_default();

    let intermediate_der = asn1::write_single(&intermediate_cert)?;
    let intermediate_cert_for_set = asn1::parse_single::<PyCertificate<'_>>(&intermediate_der)
        .map_err(|e| format!("Failed to re-parse intermediate certificate: {}", e))?;
    certs.push(CertificateChoices::Certificate(intermediate_cert_for_set));

    let mut extra_certs_der = Vec::new();
    if let Some(cert_path) = &args.cert_path {
        let extra_cert_pem =
            fs::read_to_string(cert_path).map_err(|e| format!("Failed to read extra certificate file {:?}: {}", cert_path, e))?;
        let extra_pem = pem::parse(extra_cert_pem)?;
        extra_certs_der.push(extra_pem.contents().to_vec());
        println!("Added extra certificate from {:?}", cert_path);
    }

    for der in &extra_certs_der {
        let extra_cert_for_set =
            asn1::parse_single::<PyCertificate<'_>>(der).map_err(|e| format!("Failed to re-parse extra certificate: {}", e))?;
        certs.push(CertificateChoices::Certificate(extra_cert_for_set));
    }

    let subject_cert_der = if let Some(CertificateChoices::Certificate(cert)) = certs.first() {
        asn1::write_single(cert)?
    } else {
        return Err("No subject certificate found in CMS".into());
    };

    let has_v2_attr_cert = certs.iter().any(|c| matches!(c, CertificateChoices::V2AttrCert(_)));
    let has_other_cert = certs.iter().any(|c| matches!(c, CertificateChoices::OtherCertificate(_)));
    let has_v1_attr_cert = certs.iter().any(|c| matches!(c, CertificateChoices::V1AttrCert(_)));
    signed_data.certificates = Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(certs)));

    let py_subject_cert =
        asn1::parse_single::<PyCertificate<'_>>(&subject_cert_der).map_err(|e| format!("Failed to parse subject certificate: {}", e))?;

    let ops = KeyCryptoOps {};
    let intermediate_pubkey =
        ops.public_key(&intermediate_cert).map_err(|e| format!("Failed to extract intermediate public key: {}", e))?;
    ops.verify_signed_by(&py_subject_cert, &intermediate_pubkey)
        .map_err(|e| format!("Subject certificate was not signed by the provided intermediate: {}", e))?;

    let crl_bytes = if let Some(crl_path) = args.crl_path {
        fs::read(&crl_path).map_err(|e| format!("Failed to read CRL file {:?}: {}", crl_path, e))?
    } else {
        let urls = get_crl_urls(&py_subject_cert);
        if urls.is_empty() {
            println!("Warning: No CRL distribution points found in subject certificate");
            Vec::new()
        } else {
            let mut crl_data = None;
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
            for url in &urls {
                if let Err(e) = validate_fetch_url(url) {
                    println!("Warning: Skipping CRL URL: {}", e);
                    continue;
                }
                println!("Fetching CRL from {}", url);
                match client.get(url).send() {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(bytes) = resp.bytes() {
                            crl_data = Some(bytes.to_vec());
                            break;
                        }
                    }
                    _ => continue,
                }
            }
            crl_data.unwrap_or_else(|| {
                println!("Warning: Failed to fetch CRL from any URL");
                Vec::new()
            })
        }
    };

    let mut crls: Vec<RevocationInfoChoice<'_>> = signed_data.crls.as_ref().map(|c| c.unwrap_read().clone().collect()).unwrap_or_default();

    if !crl_bytes.is_empty() {
        if let Ok(crl) = asn1::parse_single::<CertificateRevocationList<'_>>(&crl_bytes) {
            let count = crl.tbs_cert_list.revoked_certificates.as_ref().map_or(0, |rc| rc.unwrap_read().clone().count());
            let issuer_cn = get_cn_from_name(&crl.tbs_cert_list.issuer.unwrap_read()).unwrap_or_else(|| "<unknown>".to_string());
            println!("Added CRL issued by \"{}\" ({} entries)", issuer_cn, count);
        }

        let captured_content =
            asn1::parse_single::<asn1::Sequence<'_>>(&crl_bytes).map_err(|e| format!("Failed to capture CRL content: {:?}", e))?;
        crls.push(RevocationInfoChoice::Crl(captured_content));
    }

    let ocsp_bytes = if !args.ocsp {
        Vec::new()
    } else if let Some(ocsp_path) = args.ocsp_path {
        fs::read(&ocsp_path).map_err(|e| format!("Failed to read OCSP response file {:?}: {}", ocsp_path, e))?
    } else {
        let urls = get_ocsp_urls(&py_subject_cert);
        if urls.is_empty() {
            println!("Warning: No OCSP URLs found in subject certificate");
            Vec::new()
        } else {
            let ocsp_req = create_ocsp_request(&py_subject_cert, &intermediate_cert)?;
            let mut ocsp_data = None;
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
            for url in &urls {
                if let Err(e) = validate_fetch_url(url) {
                    println!("Warning: Skipping OCSP URL: {}", e);
                    continue;
                }
                println!("Fetching OCSP from {}", url);
                match client.post(url).header("Content-Type", "application/ocsp-request").body(ocsp_req.clone()).send() {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(bytes) = resp.bytes() {
                            ocsp_data = Some(bytes.to_vec());
                            break;
                        }
                    }
                    _ => continue,
                }
            }
            ocsp_data.unwrap_or_else(|| {
                println!("Warning: Failed to fetch OCSP from any URL");
                Vec::new()
            })
        }
    };

    if !ocsp_bytes.is_empty() {
        let choice = RevocationInfoChoice::Other(OtherRevocationInfoFormat {
            other_rev_info_format: x509_oid::RI_OCSP_OID,
            other_rev_info: asn1::parse_single::<asn1::Tlv<'_>>(&ocsp_bytes)
                .map_err(|e| format!("Failed to capture OCSP content: {:?}", e))?,
        });
        crls.push(choice);
        let subject_cn = get_cn_from_name(&py_subject_cert.tbs_cert.subject.unwrap_read()).unwrap_or_else(|| "<unknown>".to_string());
        let issuer_cn = get_cn_from_name(&py_subject_cert.tbs_cert.issuer.unwrap_read()).unwrap_or_else(|| "<unknown>".to_string());
        println!("Added OCSP response for \"{}\" (issuer: \"{}\")", subject_cn, issuer_cn);
    }

    // RFC 5652 paragraph 5.1: recompute SignedData version based on final contents
    let has_other_rev_info = crls.iter().any(|r| matches!(r, RevocationInfoChoice::Other(_)));

    let old_version = signed_data.version;
    signed_data.version = if has_other_rev_info || has_other_cert {
        5
    } else if has_v2_attr_cert {
        4
    } else if has_v1_attr_cert {
        3
    } else {
        signed_data.version.max(1)
    };
    if signed_data.version != old_version {
        println!("Updated SignedData version from {} to {} (RFC 5652)", old_version, signed_data.version);
    }

    // Set updated CRLs back into SignedData before encoding
    if !crls.is_empty() {
        signed_data.crls = Some(Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(crls)));
    }

    let final_sd = signed_data;

    let content_info_write =
        ContentInfo { content_type: asn1::DefinedByMarker::marker(), content: Content::SignedData(asn1::Explicit::new(final_sd)) };

    let encoded = asn1::write_single(&content_info_write).map_err(|e| format!("Failed to encode back: {:?}", e))?;

    let decoded_back_ci = asn1::parse_single::<ContentInfo>(&encoded).map_err(|e| format!("Failed to decode back: {:?}", e))?;
    let decoded_sd = match decoded_back_ci.content {
        Content::SignedData(sd) => sd.into_inner(),
        _ => return Err("Failed to decode back as SignedData: unexpected content".into()),
    };

    println!(
        "Successfully verified by decoding back. Number of certificates: {}",
        decoded_sd.certificates.as_ref().map_or(0, |c| match c {
            Asn1ReadableOrWritable::Read(s) => s.clone().count(),
            Asn1ReadableOrWritable::Write(_) => 0,
        })
    );

    if let Some(ref crls_set) = decoded_sd.crls {
        let crls_iter: Box<dyn Iterator<Item = RevocationInfoChoice<'_>>> = match crls_set {
            Asn1ReadableOrWritable::Read(s) => Box::new(s.clone()),
            Asn1ReadableOrWritable::Write(_) => Box::new(std::iter::empty()),
        };

        for (i, choice) in crls_iter.enumerate() {
            match choice {
                RevocationInfoChoice::Crl(captured) => {
                    let full_data = asn1::write_single(&captured).unwrap();
                    if let Ok(crl) = asn1::parse_single::<CertificateRevocationList<'_>>(&full_data) {
                        let count = crl.tbs_cert_list.revoked_certificates.as_ref().map_or(0, |rc| rc.unwrap_read().clone().count());
                        println!("CRL #{} has {} entries", i, count);
                    }
                }
                RevocationInfoChoice::Other(ref other) => {
                    if other.other_rev_info_format == x509_oid::RI_OCSP_OID {
                        println!("OCSP Response #{} found in CMS (format: {})", i, other.other_rev_info_format);
                    } else {
                        println!("Other Revocation Info #{} found in CMS (format: {})", i, other.other_rev_info_format);
                    }
                }
            }
        }
    }

    let base64_encoded = BASE64_STANDARD.encode(&encoded);
    let mut wrapped = String::new();
    for (i, chunk) in base64_encoded.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            wrapped.push_str("\r\n");
        }
        wrapped.push_str(std::str::from_utf8(chunk).unwrap());
    }
    wrapped.push_str("\r\n");

    let mut output_bytes = headers_bytes;
    output_bytes.extend_from_slice(wrapped.as_bytes());
    fs::write(&args.output, &output_bytes)?;
    println!("Modified CMS written to {:?}", args.output);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Modify(args) => run_modify(args),
        Commands::BerToDer(args) => ber_to_der(args),
    }
}

fn create_ocsp_request(cert: &Certificate<'_>, issuer: &Certificate<'_>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    let issuer_name_der = asn1::write_single(&cert.tbs_cert.issuer)?;

    hasher.update(&issuer_name_der);
    let issuer_name_hash = hasher.finalize_reset();

    let mut spki_hasher = sha1::Sha1::new();
    spki_hasher.update(issuer.tbs_cert.spki.subject_public_key.as_bytes());
    let issuer_key_hash = spki_hasher.finalize();

    let cert_id = CertID {
        hash_algorithm: smime::cryptography_x509::common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Sha1(Some(())),
        },
        issuer_name_hash: &issuer_name_hash,
        issuer_key_hash: &issuer_key_hash,
        serial_number: cert.tbs_cert.serial,
    };

    let requests = [Request { req_cert: cert_id, single_request_extensions: None }];

    let ocsp_req = OCSPRequest {
        tbs_request: TBSRequest {
            version: 0,
            requestor_name: None,
            request_list: Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(&requests)),
            raw_request_extensions: None,
        },
        optional_signature: None,
    };

    let req_der = asn1::write_single(&ocsp_req)?;
    Ok(req_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    fn run_ber_to_der_on(input_path: &str, test_name: &str) -> (Vec<u8>, Vec<u8>) {
        let output_path = std::env::temp_dir().join(format!("modify_cms_test_{}_{}.eml", std::process::id(), test_name));
        let args = BerToDerArgs { eml: PathBuf::from(input_path), output: output_path.clone() };
        ber_to_der(args).unwrap();
        let input_bytes = fs::read(input_path).unwrap();
        let output_bytes = fs::read(&output_path).unwrap();
        fs::remove_file(&output_path).ok();
        (input_bytes, output_bytes)
    }

    #[test]
    fn test_ber_to_der_multipart_signed() {
        let (_, output_bytes) = run_ber_to_der_on("tests/general/smime-multipart.eml", "multipart_signed");
        let message = MessageParser::default().parse(&output_bytes).unwrap();

        let sig_part = message.parts.iter().find(|p| is_pkcs7_content_type(p)).unwrap();
        let decoded = sig_part.contents().to_vec();
        let re_der = smime::utils::ber_to_der_cms(&decoded).unwrap();
        assert_eq!(decoded, re_der, "output should already be DER (idempotent)");
    }

    #[test]
    fn test_ber_to_der_x_pkcs7_signature() {
        let (_, output_bytes) = run_ber_to_der_on("tests/general/test_0_signed.eml", "x_pkcs7");
        let message = MessageParser::default().parse(&output_bytes).unwrap();

        let sig_part = message.parts.iter().find(|p| is_pkcs7_content_type(p)).unwrap();
        let decoded = sig_part.contents().to_vec();
        let re_der = smime::utils::ber_to_der_cms(&decoded).unwrap();
        assert_eq!(decoded, re_der, "output should already be DER");
    }

    #[test]
    fn test_ber_to_der_pkcs7_mime() {
        let (_, output_bytes) = run_ber_to_der_on("tests/general/pkcs7-mime.eml", "pkcs7_mime");
        let message = MessageParser::default().parse(&output_bytes).unwrap();

        let p7m_part = message.parts.iter().find(|p| is_pkcs7_content_type(p)).unwrap();
        let decoded = p7m_part.contents().to_vec();
        let re_der = smime::utils::ber_to_der_cms(&decoded).unwrap();
        assert_eq!(decoded, re_der, "output should already be DER");
    }

    #[test]
    fn test_ber_to_der_preserves_headers() {
        let (input_bytes, output_bytes) = run_ber_to_der_on("tests/general/smime-multipart.eml", "preserves_headers");

        let input_msg = MessageParser::default().parse(&input_bytes).unwrap();
        let output_msg = MessageParser::default().parse(&output_bytes).unwrap();

        assert_eq!(input_msg.from(), output_msg.from(), "From header changed");
        assert_eq!(input_msg.subject(), output_msg.subject(), "Subject header changed");
        assert_eq!(input_msg.date(), output_msg.date(), "Date header changed");
    }

    #[test]
    fn test_ber_to_der_base64_line_length() {
        let (_, output_bytes) = run_ber_to_der_on("tests/general/smime-multipart.eml", "base64_linelen");
        let message = MessageParser::default().parse(&output_bytes).unwrap();

        let sig_part = message.parts.iter().find(|p| is_pkcs7_content_type(p)).unwrap();
        let body_start = sig_part.offset_body as usize;
        let body_end = sig_part.offset_end as usize;
        let raw_body = &output_bytes[body_start..body_end];
        let body_str = String::from_utf8_lossy(raw_body);

        for line in body_str.lines() {
            assert!(line.len() <= 76, "base64 line exceeds 76 chars: {} chars", line.len());
        }
    }

    #[test]
    fn test_ber_to_der_fails_on_no_pkcs7() {
        let output_path = std::env::temp_dir().join("modify_cms_test_no_pkcs7.eml");
        let args = BerToDerArgs { eml: PathBuf::from("tests/general/no-crypto.eml"), output: output_path.clone() };
        let result = ber_to_der(args);
        assert!(result.is_err(), "should fail on .eml without PKCS#7 parts");
        fs::remove_file(&output_path).ok();
    }
}
