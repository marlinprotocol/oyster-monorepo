use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::read;
use tracing::info;

use oyster::attestation::{get, AttestationExpectations, AWS_ROOT_KEY};

use crate::args::pcr::{preset_to_pcr_preset, PcrArgs};
use crate::configs::global::DEFAULT_ATTESTATION_PORT;
use crate::types::Platform;

/// Verify Oyster Enclave Attestation
///
/// For verifying a running enclave (among other flags):
///   --enclave-ip <ENCLAVE_IP>
///
/// For verifying an existing attestation (among other flags):
///   --attestation-hex <ATTESTATION_HEX>
///
/// For verifying an existing attestation, read from a file (among other flags):
///   --attestation-hex-file <ATTESTATION_HEX_FILE>
#[derive(Args)]
pub struct VerifyArgs {
    /// Hex encoded attestation
    #[arg(short = 'x', long, conflicts_with_all = ["enclave_ip", "attestation_hex_file"])]
    attestation_hex: Option<String>,

    /// Path to file containing a hex encoded attestation
    #[arg(long, conflicts_with_all = ["enclave_ip", "attestation_hex"])]
    attestation_hex_file: Option<String>,

    /// Enclave IP
    #[arg(short = 'e', long, conflicts_with_all = ["attestation_hex", "attestation_hex_file"])]
    enclave_ip: Option<String>,

    #[command(flatten)]
    pcr: PcrArgs,

    /// Optional PCR16, hex encoded
    #[arg(long)]
    pcr16: Option<String>,

    /// Attestation user data, hex encoded
    #[arg(short = 'u', long)]
    user_data: Option<String>,

    /// Image id, hex encoded
    #[arg(short = 'i', long)]
    image_id: Option<String>,

    /// Attestation Port (default: 1300)
    #[arg(short = 'p', long, default_value_t = DEFAULT_ATTESTATION_PORT)]
    attestation_port: u16,

    /// Maximum age of attestation (in milliseconds) (default: 300000)
    #[arg(short = 'a', long, default_value = "300000")]
    max_age: u64,

    /// Attestation timestamp (in milliseconds)
    #[arg(short = 't', long, default_value = "0")]
    timestamp: u64,

    /// Root public key
    #[arg(short = 'r', long, default_value_t = hex::encode(AWS_ROOT_KEY))]
    root_public_key: String,

    /// Preset for parameters (e.g. blue, debug)
    #[arg(long)]
    preset: Option<String>,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    arch: Platform,
}

pub async fn verify(args: VerifyArgs) -> Result<()> {
    let pcrs = get_pcrs(args.pcr, args.pcr16, args.preset, args.arch)
        .context("Failed to load PCR data")?;

    // parse or fetch attestation
    let attestation = if let Some(attestation_hex) = args.attestation_hex {
        info!("Parsing attestation");
        let attestation = hex::decode(attestation_hex)?.into_boxed_slice();
        info!("Successfully parsed attestation");

        attestation
    } else if let Some(attestation_hex_file) = args.attestation_hex_file {
        info!("Reading attestation from {attestation_hex_file}");
        let attestation_hex = read(&attestation_hex_file).await?.into_boxed_slice();
        let attestation = hex::decode(attestation_hex)?.into_boxed_slice();
        info!("Read attestation from {attestation_hex_file}");

        attestation
    } else if let Some(enclave_ip) = args.enclave_ip {
        let attestation_endpoint = format!(
            "http://{}:{}/attestation/raw",
            enclave_ip, args.attestation_port
        );
        info!(
            "Connecting to attestation endpoint: {}",
            attestation_endpoint
        );

        let attestation_doc = get(attestation_endpoint.parse()?).await?;
        info!("Successfully fetched attestation document");

        attestation_doc
    } else {
        bail!("Could not get attestation, either enclave-ip, attestation-hex or attestation-hex-file must be specified")
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let user_data = args
        .user_data
        .map(|d| hex::decode(d).map_err(|_| anyhow::anyhow!("User data must be hex encoded")))
        .transpose()?;
    let root_public_key =
        hex::decode(args.root_public_key).context("Failed to decode root public key hex string")?;
    let image_id = args
        .image_id
        .map(|x| {
            hex::decode(x)
                .context("Failed to decode root public key hex string")?
                .try_into()
                .map_err(|_| anyhow!("incorrect image id size"))
        })
        .transpose()?;

    let attestation_expectations = AttestationExpectations {
        age_ms: Some((args.max_age, now)),
        pcrs,
        user_data: user_data.as_deref(),
        root_public_key: Some(root_public_key.as_slice()),
        timestamp_ms: (!args.timestamp.eq(&0)).then_some(args.timestamp),
        public_key: None,
        image_id: image_id.as_ref(),
    };

    let decoded = oyster::attestation::verify(&attestation, attestation_expectations.clone())
        .context("Failed to verify attestation document")?;

    info!("Root public key: {}", hex::encode(decoded.root_public_key));
    info!("Enclave public key: {}", hex::encode(decoded.public_key));
    info!("Image id: {}", hex::encode(&decoded.image_id));
    info!("User data: {}", hex::encode(&decoded.user_data));
    if let Ok(user_data) = String::from_utf8(decoded.user_data.to_vec()) {
        info!("User data, decoded as UTF-8: {user_data}");
    }
    info!("PCR0: {}", hex::encode(decoded.pcrs[0]));
    info!("PCR1: {}", hex::encode(decoded.pcrs[1]));
    info!("PCR2: {}", hex::encode(decoded.pcrs[2]));
    info!("PCR16: {}", hex::encode(decoded.pcrs[3]));
    info!("Verification successful ✓");
    info!(
        timestamp = attestation_expectations.timestamp_ms,
        age = attestation_expectations.age_ms.map(|x| x.0),
        pcr0 = attestation_expectations.pcrs.map(|x| hex::encode(x[0])),
        pcr1 = attestation_expectations.pcrs.map(|x| hex::encode(x[1])),
        pcr2 = attestation_expectations.pcrs.map(|x| hex::encode(x[2])),
        pcr16 = attestation_expectations.pcrs.map(|x| hex::encode(x[3])),
        enclave_public_key = attestation_expectations.public_key.map(|x| hex::encode(x)),
        user_data = attestation_expectations.user_data.map(|x| hex::encode(x)),
        root_public_key = attestation_expectations
            .root_public_key
            .map(|x| hex::encode(x)),
        image_id = attestation_expectations.image_id.map(|x| hex::encode(x)),
        "Verified against expectations: "
    );
    Ok(())
}

fn get_pcrs(
    pcr: PcrArgs,
    pcr16: Option<String>,
    preset: Option<String>,
    arch: Platform,
) -> Result<Option<[[u8; 48]; 4]>> {
    let Some((pcr0, pcr1, pcr2)) =
        pcr.load(preset.and_then(|x| preset_to_pcr_preset(&x, &arch, false)))?
    else {
        tracing::info!("No PCR values provided - skipping PCR verification");
        return Ok(None);
    };

    let pcr16 = hex::decode(pcr16.unwrap_or("00".repeat(48)))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("PCR16 must be 48 bytes"))?;

    tracing::info!(
        "Loaded PCR data: pcr0: {}, pcr1: {}, pcr2: {}, pcr16: {}",
        pcr0,
        pcr1,
        pcr2,
        hex::encode(pcr16),
    );

    Ok(Some([
        hex::decode(pcr0)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PCR0 must be 48 bytes"))?,
        hex::decode(pcr1)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PCR1 must be 48 bytes"))?,
        hex::decode(pcr2)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PCR2 must be 48 bytes"))?,
        pcr16,
    ]))
}
