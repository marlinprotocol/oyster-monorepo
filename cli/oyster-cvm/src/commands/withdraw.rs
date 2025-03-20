use crate::args::wallet::WalletArgs;
use crate::configs::global::{MIN_WITHDRAW_AMOUNT, OYSTER_MARKET_ADDRESS};
use crate::utils::{provider::create_provider, usdc::format_usdc};
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    sol,
};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

#[derive(Args)]
pub struct WithdrawArgs {
    /// Job ID
    #[arg(short, long, required = true)]
    job_id: String,

    /// Amount to withdraw in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required_unless_present = "max")]
    amount: Option<u64>,

    /// Withdraw all remaining balance
    #[arg(long, conflicts_with = "amount")]
    max: bool,

    #[command(flatten)]
    wallet: WalletArgs,
}

// Withdrawal Settings
const BUFFER_MINUTES: u64 = 7; // Required buffer time in minutes
const SCALING_FACTOR: u128 = 1_000_000_000_000; // 1e12 scaling factor for contract values

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

/// Calculate the current balance after accounting for time elapsed since last settlement
fn calculate_current_balance(balance: U256, rate: U256, last_settled: U256) -> Result<U256> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();

    let last_settled_secs =
        u64::try_from(last_settled).map_err(|_| anyhow!("Last settled time too large for u64"))?;

    if last_settled_secs > now {
        return Err(anyhow!("Last settled time is in the future"));
    }

    let elapsed_seconds = now.saturating_sub(last_settled_secs);
    debug!(
        "Time calculation: now={}, last_settled={}, elapsed_seconds={}",
        now, last_settled_secs, elapsed_seconds
    );

    // Calculate amount used since last settlement
    let amount_used = rate
        .checked_mul(U256::from(elapsed_seconds))
        .ok_or_else(|| anyhow!("Failed to calculate amount used"))?;

    debug!(
        "Balance calculation: balance={}, rate={}, amount_used={}",
        balance, rate, amount_used
    );

    // If amount used is greater than balance, return 0
    if amount_used >= balance {
        debug!(
            "Usage ({}) exceeds balance ({}), returning 0",
            amount_used, balance
        );
        return Ok(U256::ZERO);
    }

    // Calculate and return current balance after deducting used amount
    balance.checked_sub(amount_used).ok_or_else(|| {
        anyhow!(
            "Failed to calculate current balance: amount_used ({}) is greater than balance ({})",
            amount_used,
            balance
        )
    })
}

pub async fn withdraw_from_job(args: WithdrawArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;
    let max = args.max;
    let amount = args.amount;

    info!("Starting withdrawal process...");

    // Setup provider
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    info!(
        "Signer address: {:?}",
        provider
            .signer_addresses()
            .next()
            .ok_or_else(|| anyhow!("No signer address found"))?
    );

    // Create contract instance
    let market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse()
            .context("Failed to parse market address")?,
        provider.clone(),
    );

    let job_id_bytes = job_id.parse().context("Failed to parse job ID")?;

    // Check if job exists and get current balance
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    // Check if balance is zero
    if job.balance == U256::ZERO {
        return Err(anyhow!("Cannot withdraw: job balance is 0 USDC"));
    }

    // Scale down rate by 1e12
    let scaled_rate = job
        .rate
        .checked_div(U256::from(SCALING_FACTOR))
        .ok_or_else(|| anyhow!("Failed to scale rate"))?;

    // Calculate required buffer balance (5 minutes worth of rate)
    let buffer_seconds = U256::from(BUFFER_MINUTES * 60);
    let buffer_balance = scaled_rate
        .checked_mul(buffer_seconds)
        .ok_or_else(|| anyhow!("Failed to calculate buffer balance"))?;

    // Calculate current balance after accounting for elapsed time
    let current_balance = calculate_current_balance(job.balance, scaled_rate, job.lastSettled)?;

    if current_balance == U256::ZERO {
        info!("Cannot withdraw. Job is already expired.");
        return Ok(());
    }

    info!(
        "Current balance: {:.6} USDC, Required buffer: {:.6} USDC",
        format_usdc(current_balance),
        format_usdc(buffer_balance)
    );

    // Calculate maximum withdrawable amount (in USDC with 6 decimals)
    let max_withdrawable = if current_balance > buffer_balance {
        current_balance
            .checked_sub(buffer_balance)
            .ok_or_else(|| anyhow!("Failed to calculate withdrawable amount"))?
    } else {
        return Err(anyhow!(
            "Cannot withdraw: current balance ({:.6} USDC) is less than required buffer ({:.6} USDC)",
            format_usdc(current_balance),
            format_usdc(buffer_balance)
        ));
    };

    // Determine withdrawal amount (in USDC with 6 decimals)
    let amount_u256 = if max {
        info!("Maximum withdrawal requested");
        max_withdrawable
    } else {
        let amount =
            amount.ok_or_else(|| anyhow!("Amount must be specified when not using --max"))?;
        if amount < MIN_WITHDRAW_AMOUNT {
            return Err(anyhow!(
                "Amount must be at least {} (0.000001 USDC)",
                MIN_WITHDRAW_AMOUNT
            ));
        }
        let amount_u256 = U256::from(amount);
        if amount_u256 > max_withdrawable {
            return Err(anyhow!(
                "Cannot withdraw {:.6} USDC: maximum withdrawable amount is {:.6} USDC (need to maintain {:.6} USDC buffer)",
                format_usdc(amount_u256),
                format_usdc(max_withdrawable),
                format_usdc(buffer_balance)
            ));
        }
        amount_u256
    };

    info!(
        "Initiating withdrawal of {:.6} USDC",
        format_usdc(amount_u256)
    );

    // Call jobWithdraw function with amount in USDC 6 decimals
    let tx_hash = market
        .jobWithdraw(job_id_bytes, amount_u256)
        .send()
        .await
        .map_err(|e| {
            info!("Transaction failed with error: {:?}", e);
            anyhow!("Failed to send withdraw transaction: {}", e)
        })?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    info!(
        "Withdrawal transaction sent. Transaction hash: {:?}",
        tx_hash
    );

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Withdraw transaction failed - check contract interaction"
        ));
    }

    info!("Withdrawal successful!");
    Ok(())
}
