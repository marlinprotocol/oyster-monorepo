use std::str::FromStr;

use crate::args::wallet::WalletArgs;
use crate::configs::global::MIN_DEPOSIT_AMOUNT;
use crate::deployment::adapter::JobTransactionKind;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::format_usdc;
use alloy::primitives::U256;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use sui_sdk_types::Address;
use tracing::info;

/// Deposit funds to an existing job
#[derive(Args)]
pub struct DepositArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long)]
    deployment: Deployment,

    /// Job ID
    #[arg(short, long, required = true)]
    job_id: String,

    /// Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required = true)]
    amount: u64,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// USDC coin ID for Sui chain based enclave payment (optional, will be picked automatically from user's account if not provided)
    #[arg(long)]
    usdc_coin: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,
}

pub async fn deposit_to_job(args: DepositArgs) -> Result<()> {
    info!("Starting deposit...");

    let amount = args.amount;
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;

    // Input validation
    if amount < MIN_DEPOSIT_AMOUNT {
        return Err(anyhow!(
            "Amount must be at least {} (0.000001 USDC)",
            MIN_DEPOSIT_AMOUNT
        ));
    }

    // Convert amount to U256 with 6 decimals (USDC has 6 decimals)
    let amount_u256 = U256::from(amount);

    let mut chain_adapter = get_deployment_adapter(
        args.deployment,
        args.rpc,
        args.auth_token,
        args.usdc_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    // Setup provider
    let provider = chain_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Check if job exists
    let job_data = chain_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?;
    if job_data.is_none() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    let extra_decimals = chain_adapter.fetch_extra_decimals(&provider).await?;
    info!(
        "Depositing: {:.6} USDC",
        format_usdc(amount_u256, extra_decimals)
    );

    // First approve USDC transfer
    let funds = chain_adapter.prepare_funds(amount_u256, &provider).await?;

    let job_deposit_transaction = chain_adapter
        .create_job_transaction(
            JobTransactionKind::Deposit {
                job_id,
                amount: amount_u256,
            },
            Some(funds),
            &provider,
        )
        .await?;

    // Call jobDeposit function
    let _ = chain_adapter
        .send_transaction(false, job_deposit_transaction, &provider)
        .await?;

    info!("Deposit successful!");

    Ok(())
}
