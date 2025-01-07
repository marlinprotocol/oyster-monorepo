use anyhow::{Context, Result};
use hex;
use serde::Deserialize;
use std::{fs, time::{SystemTime, UNIX_EPOCH}};
use tracing::info;

use oyster::attestation::{get, verify, AttestationExpectations, AWS_ROOT_KEY};

#[derive(Deserialize)]
struct PcrValues {
    #[serde(rename = "PCR0")]
    pcr0: String,
    #[serde(rename = "PCR1")]
    pcr1: String,
    #[serde(rename = "PCR2")]
    pcr2: String,
}

pub async fn verify_enclave(
    pcr_file: &String,
    pcr0: &String,
    pcr1: &String,
    pcr2: &String,
    enclave_ip: &str,
    attestation_port: &u16,
    max_age: &usize,
    root_public_key: &str,
    timestamp: &usize,
) -> Result<()> {
    let pcrs = if !pcr_file.is_empty() {
        // Read PCRs from JSON file
        let content = fs::read_to_string(pcr_file)
            .context("Failed to read PCRs file")?;
        let pcr_values: PcrValues = serde_json::from_str(&content)
            .context("Failed to parse PCRs JSON")?;
        get_pcrs(&pcr_values.pcr0, &pcr_values.pcr1, &pcr_values.pcr2)?
    } else {
        // Use command line PCR values
        get_pcrs(pcr0, pcr1, pcr2)?
    };

    let attestation_endpoint =
        format!("http://{}:{}/attestation/raw", enclave_ip, attestation_port);
    info!(
        "Connecting to attestation endpoint: {}",
        attestation_endpoint
    );

    let attestation_doc = get(attestation_endpoint.parse()?).await?;
    info!("Successfully fetched attestation document");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as usize;
    let attestation_expectations = AttestationExpectations {
        age: Some((*max_age, now)),
        pcrs,
        root_public_key: Some(if root_public_key.is_empty() {
            AWS_ROOT_KEY.to_vec()
        } else {
            root_public_key.as_bytes().to_vec()
        }),
        timestamp: (!timestamp.eq(&0)).then_some(*timestamp),
    };

    let decoded = verify(attestation_doc, attestation_expectations)
        .context("Failed to verify attestation document")?;

    info!("Root public key: {}", hex::encode(decoded.root_public_key));
    info!("Enclave public key: {}", hex::encode(decoded.public_key));
    info!("PCR0: {}", hex::encode(decoded.pcrs[0]));
    info!("PCR1: {}", hex::encode(decoded.pcrs[1]));
    info!("PCR2: {}", hex::encode(decoded.pcrs[2]));
    info!("Verification successful ✓");
    Ok(())
}

fn get_pcrs(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Option<[[u8; 48]; 3]>> {
    if pcr0.is_empty() || pcr1.is_empty() || pcr2.is_empty() {
        return Ok(None);
    }

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
