use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
use tracing::info;

use crate::{
    args::{
        init_params::{InitParamsArgs, InitParamsList},
        pcr::{PCRS_BASE_BLUE_V1_0_0_AMD64, PCRS_BASE_BLUE_V1_0_0_ARM64},
    },
    types::Platform,
};

#[derive(Args, Debug)]
pub struct ImageArgs {
    /// Preset for parameters (e.g. blue, debug)
    #[arg(long, default_value = "blue")]
    preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    arch: Platform,

    #[command(flatten)]
    init_params: InitParamsArgs,
}

pub fn compute_image_id(args: ImageArgs) -> Result<()> {
    let pcrs = args
        .init_params
        .pcrs
        .load()
        .context("Failed to load PCRs")?
        .map(Result::Ok)
        .unwrap_or(match args.preset.as_str() {
            "blue" => match args.arch {
                Platform::AMD64 => Ok((
                    PCRS_BASE_BLUE_V1_0_0_AMD64.0.into(),
                    PCRS_BASE_BLUE_V1_0_0_AMD64.1.into(),
                    PCRS_BASE_BLUE_V1_0_0_AMD64.2.into(),
                )),
                Platform::ARM64 => Ok((
                    PCRS_BASE_BLUE_V1_0_0_ARM64.0.into(),
                    PCRS_BASE_BLUE_V1_0_0_ARM64.1.into(),
                    PCRS_BASE_BLUE_V1_0_0_ARM64.2.into(),
                )),
            },
            "debug" => Ok((
                hex::encode([0u8; 48]),
                hex::encode([0u8; 48]),
                hex::encode([0u8; 48]),
            )),
            _ => Err(anyhow!("PCRs are required")),
        })?;
    let Some(init_param_b64) = args
        .init_params
        .load(args.preset, args.arch, false)
        .context("Failed to load init params")?
    else {
        bail!("Failed to load init params");
    };

    let init_param_json = String::from_utf8(BASE64_STANDARD.decode(init_param_b64)?)?;

    let init_param: InitParamsList = serde_json::from_str(&init_param_json)?;
    let user_data = BASE64_STANDARD.decode(init_param.digest)?;

    let mut hasher = Sha256::new();

    hasher.update(hex::decode(pcrs.0).unwrap());

    hasher.update(hex::decode(pcrs.1).unwrap());

    hasher.update(hex::decode(pcrs.2).unwrap());

    hasher.update((user_data.len() as u16).to_be_bytes());

    hasher.update(user_data);

    let image_id: [u8; 32] = hasher.finalize().into();

    let hex_image_id = hex::encode(image_id);

    info!("Image ID: {}", hex_image_id);
    Ok(())
}
