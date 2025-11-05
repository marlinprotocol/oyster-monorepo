use std::str::FromStr;

use crate::args::init_params::InitParamsArgs;
use crate::args::wallet::WalletArgs;
use crate::chain::adapter::JobTransactionKind;
use crate::chain::{ChainType, get_chain_adapter};
use crate::types::Platform;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use sui_sdk_types::Address;
use tracing::info;

/// Update existing deployments
#[derive(Args)]
pub struct UpdateArgs {
    /// Deployment target
    #[arg(long, default_value = "arb1")]
    deployment: String,

    /// Job ID
    #[arg(long)]
    job_id: String,

    #[command(flatten)]
    wallet: WalletArgs,

    /// Chain (e.g. arb, sui, bsc)
    #[arg(long)]
    chain: ChainType,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// Gas coin ID for Sui chain transactions
    #[arg(long)]
    gas_coin: Option<String>,

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

pub async fn update_job(args: UpdateArgs) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;
    let debug = args.debug;
    let image_url = args.image_url;

    let mut chain_adapter = get_chain_adapter(
        args.chain,
        args.rpc,
        args.auth_token,
        None,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    let provider = chain_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    let Some(job_data) = chain_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?
    else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    let mut metadata = serde_json::from_str::<serde_json::Value>(&job_data.metadata)?;
    info!(
        "Original metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    if let Some(debug) = debug {
        metadata["debug"] = serde_json::Value::Bool(debug);
    }

    if let Some(image_url) = image_url {
        metadata["url"] = serde_json::Value::String(image_url);
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

    let job_update_transaction = chain_adapter
        .create_job_transaction(
            JobTransactionKind::Update {
                job_id,
                metadata: serde_json::to_string(&metadata)?,
            },
            None,
            &provider,
        )
        .await?;
    let _ = chain_adapter
        .send_transaction(false, job_update_transaction, &provider)
        .await?;

    Ok(())
}
