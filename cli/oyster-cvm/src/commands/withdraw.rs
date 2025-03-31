use crate::args::wallet::WalletArgs;
use crate::configs::blockchain::Blockchain;
use crate::configs::global::{
    MIN_WITHDRAW_AMOUNT, OYSTER_MARKET_ADDRESS, SOLANA_USDC_MINT_ADDRESS,
};
use crate::utils::provider::create_solana_provider;
use crate::utils::{provider::create_ethereum_provider, usdc::format_usdc};
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    sol,
};
use anchor_client::solana_sdk::system_program;
use anchor_lang::declare_program;
use anchor_lang::prelude::Pubkey;
use anchor_spl::{associated_token::get_associated_token_address, token};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use solana_transaction_status_client_types::UiTransactionEncoding;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

declare_program!(market_v);
use market_v::{
    accounts::Job as SolanaMarketVJob, client::accounts::JobWithdraw as SolanaMarketVJobWithdraw,
    client::args::JobWithdraw as SolanaMarketVJobWithdrawArgs,
};

declare_program!(oyster_credits);
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

struct JobDetails {
    balance: U256,
    rate: U256,
    last_settled: U256,
}

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

    let blockchain = Blockchain::blockchain_from_job_id(job_id.clone())?;

    info!("Starting withdrawal process...");

    let job_details = if blockchain == Blockchain::Arbitrum {
        get_ethereum_job(job_id.clone(), wallet_private_key, &blockchain).await?
    } else if blockchain == Blockchain::Solana {
        get_solana_job(job_id.clone(), wallet_private_key, &blockchain).await?
    } else {
        return Err(anyhow!("Unsupported blockchain: {:?}", blockchain.as_str()));
    };

    // Check if balance is zero
    if job_details.balance == U256::ZERO {
        return Err(anyhow!("Cannot withdraw: job balance is 0 USDC"));
    }

    // Scale down rate by 1e12
    let scaled_rate = job_details
        .rate
        .checked_div(U256::from(SCALING_FACTOR))
        .ok_or_else(|| anyhow!("Failed to scale rate"))?;

    // Calculate required buffer balance (5 minutes worth of rate)
    let buffer_seconds = U256::from(BUFFER_MINUTES * 60);
    let buffer_balance = scaled_rate
        .checked_mul(buffer_seconds)
        .ok_or_else(|| anyhow!("Failed to calculate buffer balance"))?;

    // Calculate current balance after accounting for elapsed time
    let current_balance =
        calculate_current_balance(job_details.balance, scaled_rate, job_details.last_settled)?;

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

    if blockchain == Blockchain::Arbitrum {
        withdraw_from_ethereum_job(job_id, amount_u256, wallet_private_key, blockchain).await?;
    } else if blockchain == Blockchain::Solana {
        withdraw_from_solana_job(job_id, amount_u256, wallet_private_key, blockchain).await?;
    }

    info!("Withdrawal successful!");
    Ok(())
}

async fn get_ethereum_job(
    job_id: String,
    wallet_private_key: &str,
    blockchain: &Blockchain,
) -> Result<JobDetails> {
    let provider = create_ethereum_provider(wallet_private_key, blockchain)
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

    Ok(JobDetails {
        balance: job.balance,
        rate: job.rate,
        last_settled: job.lastSettled,
    })
}

async fn get_solana_job(
    job_id: String,
    wallet_private_key: &str,
    blockchain: &Blockchain,
) -> Result<JobDetails> {
    let provider = create_solana_provider(wallet_private_key, blockchain)
        .await
        .context("Failed to create provider")?;

    let program = provider
        .program(market_v::ID)
        .context("Failed to get program")?;

    let job_index = job_id.parse::<u128>().context("Failed to parse job ID")?;

    let job_id_pa =
        Pubkey::find_program_address(&[b"job", job_index.to_le_bytes().as_ref()], &market_v::ID).0;

    let job = program.account::<SolanaMarketVJob>(job_id_pa).await?;

    Ok(JobDetails {
        balance: U256::from(job.balance),
        rate: U256::from(job.rate),
        last_settled: U256::from(job.last_settled),
    })
}

async fn withdraw_from_ethereum_job(
    job_id: String,
    amount_u256: U256,
    wallet_private_key: &str,
    blockchain: Blockchain,
) -> Result<()> {
    let provider = create_ethereum_provider(wallet_private_key, &blockchain)
        .await
        .context("Failed to create provider")?;

    // Create contract instance
    let market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse()
            .context("Failed to parse market address")?,
        provider.clone(),
    );

    let job_id_bytes = job_id.parse().context("Failed to parse job ID")?;

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

    Ok(())
}

async fn withdraw_from_solana_job(
    job_id: String,
    amount_u256: U256,
    wallet_private_key: &str,
    blockchain: Blockchain,
) -> Result<()> {
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

    let market = Pubkey::find_program_address(&[b"market"], &market_v::ID).0;
    let owner = program.payer();
    let token_mint = Pubkey::from_str(SOLANA_USDC_MINT_ADDRESS)?;
    let provider_token_account = get_associated_token_address(&job.provider, &token_mint);
    let program_token_account =
        Pubkey::find_program_address(&[b"job_token", token_mint.as_ref()], &market_v::ID).0;
    let user_token_account = get_associated_token_address(&owner, &token_mint);
    let credit_mint = Pubkey::find_program_address(&[b"credit_mint"], &oyster_credits::ID).0;
    let program_credit_token_account =
        Pubkey::find_program_address(&[b"credit_token", credit_mint.as_ref()], &market_v::ID).0;
    let user_credit_token_account = get_associated_token_address(&owner, &credit_mint);
    let state = Pubkey::find_program_address(&[b"state"], &oyster_credits::ID).0;
    let credit_program_usdc_token_account =
        Pubkey::find_program_address(&[b"program_usdc"], &oyster_credits::ID).0;

    let signature = program
        .request()
        .accounts(SolanaMarketVJobWithdraw {
            market,
            job: job_id_pa,
            owner,
            token_mint,
            provider_token_account,
            program_token_account,
            user_token_account,
            credit_mint,
            program_credit_token_account,
            user_credit_token_account,
            state,
            credit_program_usdc_token_account,
            credit_program: oyster_credits::ID,
            token_program: token::ID,
            system_program: system_program::ID,
        })
        .args(SolanaMarketVJobWithdrawArgs {
            amount: amount_u256.to::<u64>(),
            job_index,
        })
        .send()
        .await;

    if let Err(e) = signature {
        info!("Transaction failed with error: {:?}", e);
        return Err(anyhow!("Failed to send withdraw transaction: {}", e));
    }

    info!(
        "Withdrawal transaction sent. Transaction hash: {:?}",
        signature
    );

    let signature = signature.unwrap();

    let receipt = program
        .rpc()
        .get_transaction(&signature, UiTransactionEncoding::Base64)
        .await?;

    if receipt.transaction.meta.is_none() {
        return Err(anyhow!("Failed to get transaction meta"));
    }

    let meta = receipt.transaction.meta.unwrap();

    if meta.err.is_some() {
        return Err(anyhow!("Transaction failed: {:?}", meta.err.unwrap()));
    }

    Ok(())
}
