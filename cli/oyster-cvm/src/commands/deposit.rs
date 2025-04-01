use std::str::FromStr;
use std::time::Duration as StdDuration;

use crate::args::wallet::WalletArgs;
use crate::configs::blockchain::Blockchain;
use crate::configs::global::{MIN_DEPOSIT_AMOUNT, OYSTER_MARKET_ADDRESS, SOLANA_USDC_MINT_ADDRESS};
use crate::utils::provider::{create_ethereum_provider, create_solana_provider};
use crate::utils::token::approve_total_cost;
use crate::utils::usdc::format_usdc;
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    sol,
};
use anchor_client::solana_sdk::system_program;
use anchor_lang::declare_program;
use anchor_lang::prelude::Pubkey;
use anchor_spl::{associated_token::get_associated_token_address, token};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use solana_transaction_status_client_types::UiTransactionEncoding;
use tokio::time::sleep;
use tracing::{error, info};

declare_program!(market_v);
use market_v::{
    accounts::Job as SolanaMarketVJob, client::accounts::JobDeposit as SolanaMarketVJobDeposit,
    client::args::JobDeposit as SolanaMarketVJobDepositArgs,
};

declare_program!(oyster_credits);

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

    let blockchain = Blockchain::blockchain_from_job_id(args.job_id.clone())?;

    // Input validation
    if args.amount < MIN_DEPOSIT_AMOUNT {
        return Err(anyhow!(
            "Amount must be at least {} (0.000001 USDC)",
            MIN_DEPOSIT_AMOUNT
        ));
    }

    let amount_u256 = U256::from(args.amount);
    info!("Deposting: {} tokens", format_usdc(amount_u256));

    if blockchain == Blockchain::Arbitrum {
        deposit_to_ethereum_job(args, blockchain).await?;
    } else if blockchain == Blockchain::Solana {
        deposit_to_solana_job(args, blockchain).await?;
    }

    info!("Deposit successful!");

    Ok(())
}

async fn deposit_to_ethereum_job(args: DepositArgs, blockchain: Blockchain) -> Result<()> {
    // Convert amount to U256 with 6 decimals (USDC has 6 decimals)
    let amount_u256 = U256::from(args.amount);

    let wallet_private_key = &args.wallet.load_required()?;

    // Setup provider
    let provider = create_ethereum_provider(wallet_private_key, &blockchain)
        .await
        .context("Failed to create provider")?;

    // Create contract instance
    let oyster_market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse::<Address>()
            .context("Failed to parse Oyster Market address")?,
        provider.clone(),
    );

    // Check if job exists and get current balance
    let job = oyster_market
        .jobs(args.job_id.parse().context("Failed to parse job ID")?)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", args.job_id));
    }

    approve_total_cost(amount_u256, provider.clone()).await?;

    // Call jobDeposit function
    let tx_hash = oyster_market
        .jobDeposit(
            args.job_id.parse().context("Failed to parse job ID")?,
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

    Ok(())
}

async fn deposit_to_solana_job(args: DepositArgs, blockchain: Blockchain) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;

    let provider = create_solana_provider(wallet_private_key, &blockchain)
        .await
        .context("Failed to create provider")?;

    let program = provider
        .program(market_v::ID)
        .context("Failed to get program")?;

    let job_index = U256::from_str(&args.job_id).unwrap().to::<u128>();

    let job_id_pa =
        Pubkey::find_program_address(&[b"job", job_index.to_le_bytes().as_ref()], &market_v::ID).0;

    let job = program.account::<SolanaMarketVJob>(job_id_pa).await?;

    let market = Pubkey::find_program_address(&[b"market"], &market_v::ID).0;
    let owner = program.payer();
    let token_mint = Pubkey::from_str(SOLANA_USDC_MINT_ADDRESS)?;
    let owner_token_account = get_associated_token_address(&owner, &token_mint);
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
        .accounts(SolanaMarketVJobDeposit {
            market,
            job: job_id_pa,
            owner,
            token_mint,
            owner_token_account,
            provider_token_account,
            program_token_account,
            user_token_account,
            credit_mint,
            program_credit_token_account,
            user_credit_token_account,
            state,
            credit_program_usdc_token_account,
            token_program: token::ID,
            credit_program: oyster_credits::ID,
            system_program: system_program::ID,
        })
        .args(SolanaMarketVJobDepositArgs {
            amount: args.amount,
            job_index,
        })
        .send()
        .await;

    if let Err(e) = signature {
        error!("Error depositing to job: {:#?}", e);
        return Err(anyhow!("Error depositing to job"));
    }

    let signature = signature.unwrap();

    info!("Deposit transaction hash: {:?}", signature);

    // sleep for 20 seconds
    info!("Sleeping for 20 seconds before fetching transaction receipt");
    sleep(StdDuration::from_secs(20)).await;

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
