use crate::args::wallet::WalletArgs;
use crate::configs::global::{MIN_DEPOSIT_AMOUNT, OYSTER_MARKET_ADDRESS};
use crate::utils::{
    provider::create_provider,
    usdc::{approve_usdc, format_usdc},
};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    sol,
};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use tracing::info;

/// Deposit funds to an existing job
#[derive(Args)]
pub struct DepositArgs {
    /// Job ID
    #[arg(short, long, required = true)]
    job_id: String,

    /// Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required = true)]
    amount: u64,

    #[command(flatten)]
    wallet: WalletArgs,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

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

    // Setup provider
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Create contract instance
    let market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse()
            .context("Failed to parse market address")?,
        provider.clone(),
    );

    // Check if job exists and get current balance
    let job = market
        .jobs(job_id.parse().context("Failed to parse job ID")?)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }
    info!("Depositing: {:.6} USDC", format_usdc(amount_u256));

    // First approve USDC transfer
    approve_usdc(amount_u256, provider.clone()).await?;

    // Call jobDeposit function
    let tx_hash = market
        .jobDeposit(
            job_id.parse().context("Failed to parse job ID")?,
            amount_u256,
        )
        .send()
        .await
        .context("Failed to send deposit transaction")?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    info!("Deposit transaction hash: {:?}", tx_hash);

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Deposit transaction failed - check contract interaction"
        ));
    }

    info!("Deposit successful!");

    Ok(())
}
