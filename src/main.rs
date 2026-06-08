#[cfg(feature = "decrypt")]
use ::smime::decrypt_and_verify_smime_from_eml_detailed;
use ::smime::{TrustConfig, TrustStore, verify_smime_from_eml_detailed};
use clap::{Args, Parser, Subcommand};
use smime::errors::SmimeError;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub mod utils;

/// Exit codes follow the OpenSSL/NSS convention:
/// 0 = success, 1 = verification/decryption failure, 2 = operational error.
const EXIT_FAILURE: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify the S/MIME signature on a message
    Verify(VerifyArgs),

    /// Decrypt encrypted layers, then verify the enclosed signature
    #[cfg(feature = "decrypt")]
    Decrypt(DecryptArgs),
}

/// Trust anchor selection, shared by all subcommands.
///
/// The default trust anchors are the embedded Mozilla S/MIME store. `--CAfile`
/// replaces that store entirely; `--debug-anchor` appends the embedded debug
/// store to whichever base is active.
#[derive(Args)]
struct TrustArgs {
    /// PEM file of CA certificates to trust, replacing the built-in Mozilla store
    #[arg(long = "CAfile", value_name = "CA_FILE")]
    ca_file: Option<PathBuf>,

    /// Also trust the embedded debug CA certificates
    #[arg(long)]
    debug_anchor: bool,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to the .eml file
    #[arg(default_value = "./tests/general/smime-multipart.eml")]
    file: PathBuf,

    #[command(flatten)]
    trust: TrustArgs,

    /// Write the verified payload to this file
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[cfg(feature = "decrypt")]
#[derive(Parser)]
struct DecryptArgs {
    /// Path to the .eml file
    #[arg(default_value = "./tests/general/smime-multipart.eml")]
    file: PathBuf,

    #[command(flatten)]
    trust: TrustArgs,

    /// Write the decrypted payload to this file
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,

    /// Private key file (PEM or PKCS#12) to decrypt with
    #[arg(long, value_name = "KEY_FILE")]
    inkey: PathBuf,

    /// Recipient certificate (DER or PEM) for recipient matching
    #[arg(long, visible_alias = "recip", value_name = "CERT_FILE")]
    cert: PathBuf,

    /// Password for the private key / PKCS#12 keystore (used with .p12/.pfx files)
    #[arg(long, value_name = "PASSWORD", default_value = "")]
    passin: String,

    /// Password for CMS password-based decryption (PasswordRecipientInfo)
    #[arg(long, value_name = "PASSWORD")]
    password: Option<String>,

    /// Pre-shared key for KEKRecipientInfo: hex string or path to .bin file
    #[arg(long, value_name = "HEX_OR_FILE")]
    key: Option<String>,
}

#[cfg(feature = "decrypt")]
fn parse_key_arg(arg: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = hex::decode(arg) {
        return Ok(bytes);
    }
    fs::read(arg).map_err(|e| format!("--key: not valid hex and not a readable file: {}", e))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(result) => {
            println!("Result: {:#?}", result);
            if result.failures.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(EXIT_FAILURE) }
        }
        Err(message) => {
            eprintln!("{}", message);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn read_eml(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| SmimeError::ReadEml { path: path.display().to_string(), err: e.to_string() }.localize("en-UK"))?;
    println!("Read .eml file: {:?}", path);
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Write the verified/decrypted payload to `out`. Errors if there is no payload.
fn write_output(out: Option<&Path>, result: &smime::types::SmimeValidationResult) -> Result<(), String> {
    let Some(path) = out else { return Ok(()) };
    let content = result.signed_content.as_ref().ok_or("--out: no payload was produced to write")?;
    fs::write(path, content).map_err(|e| format!("Failed to write output {:?}: {}", path, e))
}

/// Assemble the trust anchors from the CLI flags: built-in Mozilla store by default,
/// replaced by `--CAfile`, with the debug store appended on `--debug-anchor`.
fn resolve_trust(args: &TrustArgs) -> Result<TrustConfig, String> {
    let mut stores = Vec::new();
    let ca_file_pem = match &args.ca_file {
        Some(path) => Some(fs::read(path).map_err(|e| format!("Failed to read CA file {:?}: {}", path, e))?),
        None => {
            stores.push(TrustStore::Builtin);
            None
        }
    };
    if args.debug_anchor {
        stores.push(TrustStore::Debug);
    }
    Ok(TrustConfig { stores, ca_file_pem })
}

fn run(cli: Cli) -> Result<smime::types::SmimeValidationResult, String> {
    match cli.command {
        Command::Verify(args) => {
            let trust = resolve_trust(&args.trust)?;
            let eml_str = read_eml(&args.file)?;
            let result = verify_smime_from_eml_detailed(eml_str, trust);
            write_output(args.out.as_deref(), &result)?;
            Ok(result)
        }

        #[cfg(feature = "decrypt")]
        Command::Decrypt(args) => {
            let trust = resolve_trust(&args.trust)?;
            let eml_str = read_eml(&args.file)?;

            let key_bytes = fs::read(&args.inkey).map_err(|e| format!("Failed to read key file {:?}: {}", args.inkey, e))?;
            let cert_bytes = fs::read(&args.cert).map_err(|e| format!("Failed to read cert file {:?}: {}", args.cert, e))?;

            let key_der = match args.inkey.extension().and_then(|e| e.to_str()) {
                Some("p12" | "pfx") => ::smime::pkcs12_utils::extract_private_key_from_p12(&key_bytes, &args.passin)
                    .map_err(|e| SmimeError::PrivateKeyParseFailed { err: e.to_string() }.localize_en_uk())?,
                _ => pem::parse(&key_bytes)
                    .map_err(|e| SmimeError::PrivateKeyParseFailed { err: e.to_string() }.localize_en_uk())?
                    .into_contents(),
            };

            let cert_der = match pem::parse(&cert_bytes) {
                Ok(p) => p.into_contents(),
                Err(_) => cert_bytes, // assume raw DER
            };

            let kek_bytes = args.key.as_deref().map(parse_key_arg).transpose()?;
            let keys = smime::decrypt::DecryptionKeys {
                private_key_der: &key_der,
                recipient_cert_der: &cert_der,
                password: args.password.as_deref(),
                kek: kek_bytes.as_deref(),
            };
            let result = decrypt_and_verify_smime_from_eml_detailed(eml_str, trust, &keys);
            write_output(args.out.as_deref(), &result)?;
            Ok(result)
        }
    }
}
