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

static PCRS_BASE_BLUE_V1_0_0_AMD64: (&str, &str, &str) = (
    "1917449cebc40efa859733b89bde39fd429df11fe9c1a0cfcd67ec9b75c1c8d9f6aa1a2ec06ce5cb7353567d1e5e4cc7",
    "70ea27296f1809c73bb61f5f08892536e1969c154f08bdccd4ff907df79881a4b14a0fc6f2ab6dd00d5b2e5a73fe88a7",
    "4a075320473f28aa39a6b92bfe344764a1352d735bf41e234480d1ccc806d1092e192d293db75a52133c27f25be5b11c",
);

pub static PCRS_BASE_BLUE_V1_0_0_ARM64: (&str, &str, &str) = (
    "cef9d589279cddbf2de41a7d94772d1501c89b50df8a40a19cfa73c8ac8e5b590b0bf434d84007e1300c5e4c3d4b572f",
    "3dc2602d18944028b4705c2b46c5d6efd73cba3c58d09deccc073075c68a4ebac36e5368eb0921c7b4c699f4ae03a1e5",
    "b946e182060c771f0c94be8882b72e051ab6bb26474ed72247e58360e94e0bb8027bf7de725f9c90d7a8e2d2bbc58d36",
);
