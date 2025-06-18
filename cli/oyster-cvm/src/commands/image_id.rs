use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
use k256::sha2::Sha384;
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

    /// Enable debug mode
    #[arg(long)]
    debug: bool,
}

pub fn compute_image_id(args: ImageArgs) -> Result<()> {
    // the preset is used here for flag since debug is not part of command line arguments
    let pcrs = args
        .init_params
        .pcrs
        .clone()
        .load_required(preset_to_pcr_preset(&args.preset, &args.arch, args.debug)) 
        .context("Failed to load PCRs")?;
    let mut pcr16 = [0u8; 48];
    if let Some(init_param_b64) = args
        .init_params
        .load(args.preset, args.arch, false)
        .context("Failed to load init params")?
    {
        let init_param_json = String::from_utf8(BASE64_STANDARD.decode(init_param_b64)?)?;

        let init_param: InitParamsList = serde_json::from_str(&init_param_json)?;
        let digest = BASE64_STANDARD.decode(init_param.digest)?;

        let mut pcr_hasher = Sha384::new();
        pcr_hasher.update([0u8; 48]);
        pcr_hasher.update(digest);
        pcr16 = pcr_hasher.finalize().into();
    };

    let mut hasher = Sha256::new();
    // bitflags denoting what pcrs are part of the computation
    // this one has 0, 1, 2 and 16
    hasher.update(&((1u32 << 0) | (1 << 1) | (1 << 2) | (1 << 16)).to_be_bytes());
    hasher.update(hex::decode(pcrs.0).unwrap());
    hasher.update(hex::decode(pcrs.1).unwrap());
    hasher.update(hex::decode(pcrs.2).unwrap());
    hasher.update(pcr16);

    let image_id: [u8; 32] = hasher.finalize().into();

    let hex_image_id = hex::encode(image_id);

    info!("Image ID: {}", hex_image_id);
    Ok(())
}
