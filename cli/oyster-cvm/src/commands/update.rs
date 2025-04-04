use crate::args::init_params::InitParamsArgs;
use crate::configs::blockchain::{Blockchain, SOLANA_TRANSACTION_CONFIG};
use crate::types::Platform;
use crate::utils::provider::{create_ethereum_provider, create_solana_provider};
use crate::utils::solana::fetch_transaction_receipt_with_retry;
use crate::{args::wallet::WalletArgs, configs::global::OYSTER_MARKET_ADDRESS};
use alloy::sol;
use anchor_lang::{declare_program, prelude::Pubkey};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use tracing::info;

declare_program!(market_v);
use market_v::{
    accounts::Job as SolanaMarketVJob,
    client::accounts::JobMetadataUpdate as SolanaMarketVJobMetadataUpdate,
    client::args::JobMetadataUpdate as SolanaMarketVJobMetadataUpdateArgs,
};

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
    #[arg(long, default_value = Platform::ARM64.as_str())]
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
    let job_id = args.job_id.clone();

    let blockchain = Blockchain::blockchain_from_job_id(job_id.clone())?;

    if blockchain == Blockchain::Arbitrum {
        update_ethereum_job(args, blockchain).await?;
    } else if blockchain == Blockchain::Solana {
        update_solana_job(args, blockchain).await?;
    } else {
        return Err(anyhow!("Unsupported blockchain"));
    }

    Ok(())
}

async fn update_ethereum_job(args: UpdateArgs, blockchain: Blockchain) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let debug = args.debug;
    let image_url = args.image_url;
    let job_id = args.job_id.clone();

    let provider = create_ethereum_provider(wallet_private_key, &blockchain)
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

async fn update_solana_job(args: UpdateArgs, blockchain: Blockchain) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let debug = args.debug;
    let image_url = args.image_url;
    let job_id = args.job_id.clone();

    let provider = create_solana_provider(wallet_private_key, &blockchain)
        .await
        .context("Failed to create provider")?;

    let program = provider
        .program(market_v::ID)
        .context("Failed to get program")?;

    let job_index = job_id.parse::<u128>().context("Failed to parse job ID")?;

    let job_id_pa =
        Pubkey::find_program_address(&[b"job", job_index.to_le_bytes().as_ref()], &market_v::ID).0;

    let job = program.account::<SolanaMarketVJob>(job_id_pa).await?;

    let mut metadata = serde_json::from_str::<serde_json::Value>(&job.metadata)?;

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

    let market = Pubkey::find_program_address(&[b"market"], &market_v::ID).0;
    let owner = program.payer();

    let signature = program
        .request()
        .accounts(SolanaMarketVJobMetadataUpdate {
            market,
            job: job_id_pa,
            owner,
        })
        .args(SolanaMarketVJobMetadataUpdateArgs {
            new_metadata: serde_json::to_string(&metadata)?,
            job_index,
        })
        .send_with_spinner_and_config(SOLANA_TRANSACTION_CONFIG)
        .await;

    if let Err(e) = signature {
        info!("Transaction failed with error: {:?}", e);
        return Err(anyhow!("Failed to send update transaction: {}", e));
    }

    info!("Update transaction sent. Transaction hash: {:?}", signature);

    let signature = signature.unwrap();

    fetch_transaction_receipt_with_retry(program, &signature).await?;

    Ok(())
}
