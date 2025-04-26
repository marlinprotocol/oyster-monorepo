use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
use tracing::info;

use crate::{
    args::{
        init_params::{InitParamsArgs, InitParamsList},
        pcr::preset_to_pcr_preset,
    },
    types::Platform,
};

/// Get Image ID
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
        .clone()
        .load_required(preset_to_pcr_preset(&args.preset, &args.arch))
        .context("Failed to load PCRs")?;
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
