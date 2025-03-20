use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct PcrArgs {
    /// Preset PCRs for known enclave images
    #[arg(long, conflicts_with_all = ["pcr0", "pcr1", "pcr2", "pcr_json"])]
    pub pcr_preset: Option<String>,

    /// Path to PCR JSON file
    #[arg(short = 'j', long, conflicts_with_all = ["pcr0", "pcr1", "pcr2", "pcr_preset"])]
    pub pcr_json: Option<String>,

    /// PCR 0 value
    #[arg(short = '0', long, conflicts_with_all = ["pcr_json", "pcr_preset"], requires_all = ["pcr1", "pcr2"])]
    pub pcr0: Option<String>,

    /// PCR 1 value
    #[arg(short = '1', long, conflicts_with_all = ["pcr_json", "pcr_preset"], requires_all = ["pcr0", "pcr2"])]
    pub pcr1: Option<String>,

    /// PCR 2 value
    #[arg(short = '2', long, conflicts_with_all = ["pcr_json", "pcr_preset"], requires_all = ["pcr0", "pcr1"])]
    pub pcr2: Option<String>,
}

impl PcrArgs {
    pub fn load(&self) -> Result<Option<(String, String, String)>> {
        if let Some(ref path) = self.pcr_json {
            let file = std::fs::File::open(path)?;
            let json: serde_json::Value =
                serde_json::from_reader(file).context("Failed to parse PCR JSON file")?;
            let json_obj = json
                .as_object()
                .context("PCR data should be a JSON object")?;
            let lower_keys_map: std::collections::HashMap<_, _> = json_obj
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v))
                .collect();

            return Ok(Some((
                lower_keys_map
                    .get("pcr0")
                    .and_then(|v| v.as_str())
                    .ok_or(anyhow!("Missing PCR0"))?
                    .into(),
                lower_keys_map
                    .get("pcr1")
                    .and_then(|v| v.as_str())
                    .ok_or(anyhow!("Missing PCR1"))?
                    .into(),
                lower_keys_map
                    .get("pcr2")
                    .and_then(|v| v.as_str())
                    .ok_or(anyhow!("Missing PCR2"))?
                    .into(),
            )));
        }

        if let Some(ref name) = self.pcr_preset {
            return match name.as_str() {
                "base/blue/v1.0.0/amd64" => Ok(Some((
                    PCRS_BASE_BLUE_V1_0_0_AMD64.0.into(),
                    PCRS_BASE_BLUE_V1_0_0_AMD64.1.into(),
                    PCRS_BASE_BLUE_V1_0_0_AMD64.2.into(),
                ))),
                "base/blue/v1.0.0/arm64" => Ok(Some((
                    PCRS_BASE_BLUE_V1_0_0_ARM64.0.into(),
                    PCRS_BASE_BLUE_V1_0_0_ARM64.1.into(),
                    PCRS_BASE_BLUE_V1_0_0_ARM64.2.into(),
                ))),
                _ => bail!("Unknown PCR preset"),
            };
        }

        // Only checking one PCR - requires_all enforces mutual presence of all PCRs
        if self.pcr0.is_none() {
            return Ok(None);
        }

        let pcr0 = self.pcr0.as_ref().unwrap().clone();
        let pcr1 = self.pcr1.as_ref().unwrap().clone();
        let pcr2 = self.pcr2.as_ref().unwrap().clone();

        Ok(Some((pcr0, pcr1, pcr2)))
    }
}

pub static PCRS_BASE_BLUE_V1_0_0_AMD64: (&str, &str, &str) = (
    "181023664fd6477acdb28bb3d7b7e5eff6001a7a8c2d32309e076460fa6cda213cee6c4c0b97c96421bf6b1b74305030",
    "70ea27296f1809c73bb61f5f08892536e1969c154f08bdccd4ff907df79881a4b14a0fc6f2ab6dd00d5b2e5a73fe88a7",
    "c631afd653305f3a40f21579897d9308daa3145eff263b1f2875ac86d2ad800e3a7ebaf7fcd39e5485896cd94607e74e",
);

pub static PCRS_BASE_BLUE_V1_0_0_ARM64: (&str, &str, &str) = (
    "dcb80432f49fbc0ee320e0f48abcca99962d3620bc1442b22d3bf4a60518e0295576c3cffe94a451c700f46e548c1ca9",
    "3dc2602d18944028b4705c2b46c5d6efd73cba3c58d09deccc073075c68a4ebac36e5368eb0921c7b4c699f4ae03a1e5",
    "7c6df87340416213e7ed9aae80a766626a9fa5a02adcb1d64ee170aa08357a274b261a8ab94723ba600b910282e52d92",
);
