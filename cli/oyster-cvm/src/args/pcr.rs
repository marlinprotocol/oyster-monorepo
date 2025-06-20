use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json;
use tracing::info;

use crate::types::Platform;

#[derive(Args, Debug, Clone)]
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
    pub fn load(self, default_preset: Option<String>) -> Result<Option<(String, String, String)>> {
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

        // Only checking one PCR - requires_all enforces mutual presence of all PCRs
        if self.pcr0.is_some() {
            let pcr0 = self.pcr0.as_ref().unwrap().clone();
            let pcr1 = self.pcr1.as_ref().unwrap().clone();
            let pcr2 = self.pcr2.as_ref().unwrap().clone();

            return Ok(Some((pcr0, pcr1, pcr2)));
        }

        if let Some(ref name) = self.pcr_preset.or(default_preset) {
            info!(name, "PCR preset");
            return match name.as_str() {
                "base/blue/v3.0.0/amd64" => Ok(Some((
                    PCRS_BASE_BLUE_V3_0_0_AMD64.0.into(),
                    PCRS_BASE_BLUE_V3_0_0_AMD64.1.into(),
                    PCRS_BASE_BLUE_V3_0_0_AMD64.2.into(),
                ))),
                "base/blue/v3.0.0/arm64" => Ok(Some((
                    PCRS_BASE_BLUE_V3_0_0_ARM64.0.into(),
                    PCRS_BASE_BLUE_V3_0_0_ARM64.1.into(),
                    PCRS_BASE_BLUE_V3_0_0_ARM64.2.into(),
                ))),
                "base/blue/v2.0.0/amd64" => Ok(Some((
                    PCRS_BASE_BLUE_V2_0_0_AMD64.0.into(),
                    PCRS_BASE_BLUE_V2_0_0_AMD64.1.into(),
                    PCRS_BASE_BLUE_V2_0_0_AMD64.2.into(),
                ))),
                "base/blue/v2.0.0/arm64" => Ok(Some((
                    PCRS_BASE_BLUE_V2_0_0_ARM64.0.into(),
                    PCRS_BASE_BLUE_V2_0_0_ARM64.1.into(),
                    PCRS_BASE_BLUE_V2_0_0_ARM64.2.into(),
                ))),
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
                // To be used by verify and compute-image-id command
                "debug" => Ok(Some((
                    hex::encode([0u8; 48]),
                    hex::encode([0u8; 48]),
                    hex::encode([0u8; 48]),
                ))),
                _ => bail!("Unknown PCR preset"),
            };
        }

        Ok(None)
    }

    pub fn load_required(self, default_preset: Option<String>) -> Result<(String, String, String)> {
        self.load(default_preset)
            .transpose()
            .ok_or(anyhow!("Pcrs parameter is required."))?
    }
}

pub fn preset_to_pcr_preset(preset: &str, arch: &Platform, debug: bool) -> Option<String> {
    // if debug flag is true, return debug pcr preset
    if debug {
        return Some("debug".to_owned());
    }

    match preset {
        "blue" => match arch {
            Platform::AMD64 => Some("base/blue/v3.0.0/amd64"),
            Platform::ARM64 => Some("base/blue/v3.0.0/arm64"),
        },
        "debug" => Some("debug"),
        _ => None,
    }
    .map(str::to_owned)
}

pub static PCRS_BASE_BLUE_V3_0_0_AMD64: (&str, &str, &str) = (
    "7d08525c48ff4b28d4539924f9944957cb30973be51a3bcefa2a284e504d91636d35be6d17fed21a520a755f115b0330",
    "ed7759aa996a2e94c6086f24f61f354f75f9ea7f93a74f55d65c2cb5590d1af3930c9adbc57bb543764fa1f5c444f495",
    "4b23d52967848dbbb7a4b8373282c9fa1629e65febf04d4887ac3f58e4a98ca7519b3d0512fec4008dfa09b5c41b99c1",
);

pub static PCRS_BASE_BLUE_V3_0_0_ARM64: (&str, &str, &str) = (
    "3aa0e6e6ed7d8301655fced7e6ddcc443a3e57bf62f070caa6becf337069e859c0f03d68136440ff1cab8adefd20634c",
    "b0d319fa64f9c2c9d7e9187bc21001ddacfab4077e737957fa1b8b97cc993bed43a79019aebfd40ee5f6f213147909f8",
    "fdb2295dc5d9b67a653ed5f3ead5fc8166ec3cae1de1c7c6f31c3b43b2eb26ab5d063f414f3d2b93163426805dfe057e",
);

pub static PCRS_BASE_BLUE_V2_0_0_AMD64: (&str, &str, &str) = (
    "862b295eefd03db5132be44464d8280728ccd7cc4513284ad4e9dfa923c93e8df2ebcf37b8728f2de75e48e0ea1d2c1c",
    "ed7759aa996a2e94c6086f24f61f354f75f9ea7f93a74f55d65c2cb5590d1af3930c9adbc57bb543764fa1f5c444f495",
    "ca759b0a285727e01471c49a42a3ca079f480963f90cc73b28e645ff95d85f006c149561970a54053e0e8a51d7c288ca",
);

pub static PCRS_BASE_BLUE_V2_0_0_ARM64: (&str, &str, &str) = (
    "8ef3a8e2631d6fa53e0a75e7a38072df2da40fe3d9b777c6673a738aa8df5e21bfdc772c8935f12567b10fd10353e7aa",
    "b0d319fa64f9c2c9d7e9187bc21001ddacfab4077e737957fa1b8b97cc993bed43a79019aebfd40ee5f6f213147909f8",
    "3daa3181531f1d80c00ef5ff846e0ff8ed5298dff3472fb9fbaf1bb76f54452937f6645371f01f492cabf1793517c361",
);

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
