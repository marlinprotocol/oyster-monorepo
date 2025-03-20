use crate::utils::provider::create_provider;
use crate::{args::wallet::WalletArgs, configs::global::OYSTER_MARKET_ADDRESS};
use alloy::sol;
use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

#[derive(Args)]
pub struct UpdateArgs {
    /// Job ID
    #[arg(short, long)]
    job_id: String,

    #[command(flatten)]
    wallet: WalletArgs,

    /// New URL of the enclave image
    #[arg(short, long)]
    image_url: Option<String>,

    /// New debug mode
    #[arg(short, long)]
    debug: Option<bool>,
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
        metadata["debug"] = serde_json::Value::Bool(debug);
    }

    if let Some(image_url) = image_url {
        metadata["url"] = serde_json::Value::String(image_url.into());
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
