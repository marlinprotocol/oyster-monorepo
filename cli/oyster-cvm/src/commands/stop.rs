use crate::args::wallet::WalletArgs;
use crate::chain::adapter::JobTransactionKind;
use crate::chain::{ChainType, get_chain_adapter};
use alloy::primitives::U256;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use std::str::FromStr;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::time::sleep;
use tracing::info;

/// Stop an Oyster CVM instance
#[derive(Args)]
pub struct StopArgs {
    /// Deployment target
    #[arg(long, default_value = "arb1")]
    deployment: String,

    /// Job ID
    #[arg(short = 'j', long, required = true)]
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
}

pub async fn stop_oyster_instance(args: StopArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;

    info!("Stopping oyster instance with:");
    info!("  Job ID: {}", job_id);

    let mut chain_adapter = get_chain_adapter(
        args.chain,
        args.rpc,
        args.auth_token,
        None,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    // Setup provider
    let provider = chain_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    info!("Signer address: {:?}", chain_adapter.get_sender_address());

    // Check if job exists
    let job_data = chain_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?;
    if job_data.is_none() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    // First, set the job's rate to 0 using the jobReviseRateInitiate call.
    info!("Found job, initiating rate update to 0...");
    let job_revise_rate_transaction = chain_adapter
        .create_job_transaction(
            JobTransactionKind::ReviseRateInitiate {
                job_id: job_id.clone(),
                rate: U256::from(0),
            },
            None,
            &provider,
        )
        .await?;
    let _ = chain_adapter
        .send_transaction(false, job_revise_rate_transaction, &provider)
        .await
        .context("Failed to send rate revise transaction")?;

    info!("Job rate updated successfully to 0!");

    // Wait for 5 minutes before closing the job.
    info!("Waiting for 5 minutes before closing the job...");
    sleep(Duration::from_secs(300)).await;

    // Check if job is already closed before attempting to close
    let job_exists = chain_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?;
    if job_exists.is_none() {
        info!("Job is already closed!");
        return Ok(());
    }

    // Only proceed with closing if job still exists
    info!("Initiating job close...");
    let job_close_transaction = chain_adapter
        .create_job_transaction(JobTransactionKind::Close { job_id }, None, &provider)
        .await?;
    let _ = chain_adapter
        .send_transaction(false, job_close_transaction, &provider)
        .await
        .context("Failed to send stop transaction")?;

    info!("Instance stopped successfully!");
    Ok(())
}
