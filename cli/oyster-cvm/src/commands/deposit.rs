use crate::configs::global::{CREDIT_MANAGER_ADDRESS, MIN_DEPOSIT_AMOUNT};
use crate::utils::credit::{approve_credit, get_credit_balance};
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
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CreditManager,
    "src/abis/credit_manager_abi.json"
);

pub async fn deposit_to_job(job_id: &str, amount: u64, wallet_private_key: &str) -> Result<()> {
    info!("Starting deposit...");

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
    let credit_manager =
        CreditManager::new(CREDIT_MANAGER_ADDRESS.parse::<Address>()?, provider.clone());

    // Check if job exists and get current balance
    let job = credit_manager
        .jobs(job_id.parse().context("Failed to parse job ID")?)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.user == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    let credit_balance = get_credit_balance(provider.clone()).await?;

    let credit_amount = std::cmp::min(credit_balance, amount_u256);
    let token_amount = amount_u256 - credit_amount;

    if credit_amount > U256::from(0) {
        info!("Depositing {} credits", format_usdc(credit_amount));
        approve_credit(credit_amount, provider.clone()).await?;
    }
    if token_amount > U256::from(0) {
        info!("Depositing {} USDC", format_usdc(token_amount));
        approve_usdc(token_amount, provider.clone()).await?;
    }

    // Call jobDeposit function
    let tx_hash = credit_manager
        .jobDeposit(
            job_id.parse().context("Failed to parse job ID")?,
            credit_amount,
            token_amount,
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
