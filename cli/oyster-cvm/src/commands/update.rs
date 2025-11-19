use crate::args::init_params::InitParamsArgs;
use crate::types::Platform;
use crate::utils::provider::create_provider;
use crate::{args::wallet::WalletArgs, configs::global::OYSTER_MARKET_ADDRESS};
use alloy::sol;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Update existing deployments
#[derive(Args)]
pub struct UpdateArgs {
    /// Job ID
    #[arg(long)]
    job_id: String,

    #[command(flatten)]
    wallet: WalletArgs,

    /// New URL of the enclave image
    #[arg(long)]
    image_url: Option<String>,

    /// New debug mode
    #[arg(short, long)]
    debug: Option<bool>,

    /// Preset for init params (e.g. blue)
    #[arg(long, default_value = "blue")]
    preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    arch: Platform,

    /// New init params
    #[command(flatten)]
    init_params: InitParamsArgs,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn update_job(args: UpdateArgs) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;
    let debug = args.debug;
    let image_url = args.image_url;

    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    let market = OysterMarket::new(OYSTER_MARKET_ADDRESS.parse()?, provider);

    let mut metadata = serde_json::from_str::<serde_json::Value>(
        &market.jobs(job_id.parse()?).call().await?.metadata,
    )?;
    info!(
        "Original metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    if let Some(debug) = debug {
        // Check if existing init_params contain contract-address when enabling debug mode
        if debug && metadata.get("init_params").is_some() {
            if let Some(init_params_str) = metadata["init_params"].as_str() {
                // Decode the base64 init_params to check for contract-address
                if let Ok(decoded_bytes) =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, init_params_str)
                {
                    if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                        if let Ok(init_params_json) =
                            serde_json::from_str::<serde_json::Value>(&decoded_str)
                        {
                            if let Some(params) =
                                init_params_json.get("params").and_then(|p| p.as_array())
                            {
                                for param in params {
                                    if let Some(path) = param.get("path").and_then(|p| p.as_str()) {
                                        if path == "contract-address" {
                                            return Err(anyhow!(
                                                "Refused to enable debug mode for job with contract address. It is not safe to use contract address in debug mode since it can expose sensitive contract interactions."
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        metadata["debug"] = serde_json::Value::Bool(debug);
    }

    if let Some(image_url) = image_url {
        metadata["url"] = serde_json::Value::String(image_url.into());
    }

    if let Some(init_params) = args
        .init_params
        .load(
            args.preset,
            args.arch,
            metadata["debug"].as_bool().unwrap_or(false),
        )
        .context("Failed to load init params")?
    {
        metadata["init_params"] = init_params.into();
    }

    info!(
        "Updated metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    let tx_hash = market
        .jobMetadataUpdate(job_id.parse()?, serde_json::to_string(&metadata)?)
        .send()
        .await?
        .watch()
        .await?;

    info!("Metadata update transaction: {:?}", tx_hash);

    Ok(())
}
