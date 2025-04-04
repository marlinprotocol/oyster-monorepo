use crate::configs::blockchain::{Blockchain, SOLANA_TRANSACTION_CONFIG};
use crate::configs::global::SOLANA_USDC_MINT_ADDRESS;
use crate::utils::provider::{create_ethereum_provider, create_solana_provider};
use crate::utils::solana::fetch_transaction_receipt_with_retry;
use crate::{args::wallet::WalletArgs, configs::global::OYSTER_MARKET_ADDRESS};
use alloy::{
    primitives::{Address, B256},
    providers::{Provider, WalletProvider},
    sol,
};
use anchor_client::solana_sdk::system_program;
use anchor_lang::declare_program;
use anchor_lang::prelude::Pubkey;
use anchor_spl::{associated_token::get_associated_token_address, token};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::str::FromStr;
use tracing::info;

declare_program!(market_v);
use market_v::{
    accounts::Job as SolanaMarketVJob, client::accounts::JobClose as SolanaMarketVJobClose,
    client::args::JobClose as SolanaMarketVJobCloseArgs,
};

declare_program!(oyster_credits);

#[derive(Args)]
pub struct StopArgs {
    /// Job ID
    #[arg(short = 'j', long, required = true)]
    job_id: String,

    #[command(flatten)]
    wallet: WalletArgs,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn stop_oyster_instance(args: StopArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;

    info!("Stopping oyster instance with:");
    info!("  Job ID: {}", job_id);

    let blockchain = Blockchain::blockchain_from_job_id(job_id.clone())?;

    if blockchain == Blockchain::Arbitrum {
        stop_ethereum_oyster_instance(job_id, wallet_private_key, blockchain).await?;
    } else if blockchain == Blockchain::Solana {
        stop_solana_oyster_instance(job_id, wallet_private_key, blockchain).await?;
    } else {
        return Err(anyhow!("Unsupported blockchain"));
    }

    info!("Instance stopped successfully!");
    Ok(())
}

async fn stop_ethereum_oyster_instance(
    job_id: String,
    wallet_private_key: &str,
    blockchain: Blockchain,
) -> Result<()> {
    let provider = create_ethereum_provider(wallet_private_key, &blockchain)
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
    let market_address = OYSTER_MARKET_ADDRESS
        .parse()
        .context("Failed to parse market address")?;
    let market = OysterMarket::new(market_address, provider);

    // Parse job ID once
    let job_id_bytes = job_id.parse::<B256>().context("Failed to parse job ID")?;

    // Check if job exists
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    // Check if job is already closed before attempting to close
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch job details")?;

    if job.owner == Address::ZERO {
        info!("Job is already closed!");
        return Ok(());
    }

    info!("Found job, closing...");

    let send_result = market.jobClose(job_id_bytes).send().await;
    let tx_hash = match send_result {
        Ok(tx_call_result) => tx_call_result
            .watch()
            .await
            .context("Failed to get transaction hash for job close")?,
        Err(err) => {
            return Err(anyhow!("Failed to send stop transaction: {:?}", err));
        }
    };

    info!("Stop transaction sent: {:?}", tx_hash);

    // Verify jobClose transaction success.
    let receipt = market
        .provider()
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt for job close")?
        .ok_or_else(|| anyhow!("Job close transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Job close transaction failed - check contract interaction"
        ));
    }

    Ok(())
}

async fn stop_solana_oyster_instance(
    job_id: String,
    wallet_private_key: &str,
    blockchain: Blockchain,
) -> Result<()> {
    let provider = create_solana_provider(wallet_private_key, &blockchain)
        .await
        .context("Failed to create provider")?;

    let program = provider
        .program(market_v::ID)
        .context("Failed to get program")?;

    info!("Signer address: {:?}", program.payer());

    let job_index = job_id.parse::<u128>().context("Failed to parse job ID")?;

    let job_id_pa =
        Pubkey::find_program_address(&[b"job", job_index.to_le_bytes().as_ref()], &market_v::ID).0;

    let job = program.account::<SolanaMarketVJob>(job_id_pa).await;

    if job.is_err() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    let job = job.unwrap();

    info!("Found job, closing...");

    let market = Pubkey::find_program_address(&[b"market"], &market_v::ID).0;
    let owner = program.payer();
    let token_mint = Pubkey::from_str(SOLANA_USDC_MINT_ADDRESS)?;
    let program_token_account =
        Pubkey::find_program_address(&[b"job_token", token_mint.as_ref()], &market_v::ID).0;
    let provider_token_account = get_associated_token_address(&job.provider, &token_mint);
    let credit_mint = Pubkey::find_program_address(&[b"credit_mint"], &oyster_credits::ID).0;
    let program_credit_token_account =
        Pubkey::find_program_address(&[b"credit_token", credit_mint.as_ref()], &market_v::ID).0;
    let state = Pubkey::find_program_address(&[b"state"], &oyster_credits::ID).0;
    let credit_program_usdc_token_account =
        Pubkey::find_program_address(&[b"program_usdc"], &oyster_credits::ID).0;

    let user_token_account = get_associated_token_address(&job.owner, &token_mint);
    let user_credit_token_account = get_associated_token_address(&job.owner, &credit_mint);

    let signature = program
        .request()
        .accounts(SolanaMarketVJobClose {
            market,
            job: job_id_pa,
            token_mint,
            program_token_account,
            user_token_account,
            provider_token_account,
            credit_mint,
            program_credit_token_account,
            user_credit_token_account,
            owner,
            state,
            credit_program_usdc_token_account,
            credit_program: oyster_credits::ID,
            token_program: token::ID,
            system_program: system_program::ID,
        })
        .args(SolanaMarketVJobCloseArgs { job_index })
        .send_with_spinner_and_config(SOLANA_TRANSACTION_CONFIG)
        .await;

    let tx_hash = match signature {
        Ok(signature) => signature,
        Err(err) => {
            return Err(anyhow!("Failed to send stop transaction: {:?}", err));
        }
    };

    info!("Stop transaction sent: {:?}", tx_hash);

    fetch_transaction_receipt_with_retry(program, &tx_hash).await?;

    Ok(())
}
