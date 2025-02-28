use anyhow::{Context, Result};
use clap::Args;
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use oyster::attestation::{get, AttestationExpectations, AWS_ROOT_KEY};

use crate::args::pcr::PcrArgs;

#[derive(Args)]
pub struct VerifyArgs {
    /// Enclave IP
    #[arg(short = 'e', long, required = true)]
    enclave_ip: String,

    #[command(flatten)]
    pcr: PcrArgs,

    /// Attestation user data, hex encoded
    #[arg(short = 'u', long)]
    user_data: Option<String>,

    /// Attestation Port (default: 1300)
    #[arg(short = 'p', long, default_value = "1300")]
    attestation_port: u16,

    /// Maximum age of attestation (in milliseconds) (default: 300000)
    #[arg(short = 'a', long, default_value = "300000")]
    max_age: usize,

    /// Attestation timestamp (in milliseconds)
    #[arg(short = 't', long, default_value = "0")]
    timestamp: usize,

    /// Root public key
    #[arg(short = 'r', long, default_value_t = hex::encode(AWS_ROOT_KEY))]
    root_public_key: String,
}

pub async fn verify(args: VerifyArgs) -> Result<()> {
    let pcrs = get_pcrs(&args.pcr).context("Failed to load PCR data")?;

    let attestation_endpoint = format!(
        "http://{}:{}/attestation/raw",
        args.enclave_ip, args.attestation_port
    );
    info!(
        "Connecting to attestation endpoint: {}",
        attestation_endpoint
    );

    let attestation_doc = get(attestation_endpoint.parse()?).await?;
    info!("Successfully fetched attestation document");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as usize;
    let user_data = args
        .user_data
        .map(|d| hex::decode(d).map_err(|_| anyhow::anyhow!("User data must be hex encoded")))
        .transpose()?;
    let root_public_key =
        hex::decode(args.root_public_key).context("Failed to decode root public key hex string")?;

    let attestation_expectations = AttestationExpectations {
        age: Some((args.max_age, now)),
        pcrs,
        user_data: user_data.as_ref().map(|x| x.as_slice()),
        root_public_key: Some(root_public_key.as_slice()),
        timestamp: (!args.timestamp.eq(&0)).then_some(args.timestamp),
        public_key: None,
    };

    let decoded = oyster::attestation::verify(&attestation_doc, attestation_expectations)
        .context("Failed to verify attestation document")?;

    info!("Root public key: {}", hex::encode(decoded.root_public_key));
    info!("Enclave public key: {}", hex::encode(decoded.public_key));
    info!("User data: {}", hex::encode(&decoded.user_data));
    if let Ok(user_data) = String::from_utf8(decoded.user_data.to_vec()) {
        info!("User data, decoded as UTF-8: {user_data}");
    }
    info!("PCR0: {}", hex::encode(decoded.pcrs[0]));
    info!("PCR1: {}", hex::encode(decoded.pcrs[1]));
    info!("PCR2: {}", hex::encode(decoded.pcrs[2]));
    info!("Verification successful ✓");
    Ok(())
}

fn get_pcrs(pcr: &PcrArgs) -> Result<Option<[[u8; 48]; 3]>> {
    let Some((pcr0, pcr1, pcr2)) = pcr.load()? else {
        tracing::info!("No PCR values provided - skipping PCR verification");
        return Ok(None);
    };

    tracing::info!(
        "Loaded PCR data: pcr0: {}, pcr1: {}, pcr2: {}",
        pcr0,
        pcr1,
        pcr2
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
    ]))
}
