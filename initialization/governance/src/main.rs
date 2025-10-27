mod config;
mod crypto;
mod governance_contract;
mod hash;
mod server;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::{join, sync::RwLock};
use std::sync::Arc;

use config::load_app_config;
use crypto::{derive_public_key, fetch_encryption_key, fetch_signing_key, setup_libsodium};
use governance_contract::{
    GovernanceConfig, GovernanceContract, fetch_chain_contexts, fetch_total_supply, tally_votes,
};
use hash::{compute_result_hash, compute_vote_result_hash, serialize_vote_result};
use server::serve_result_api;
use types::{Args, VoteResult};

use crate::{governance_contract::fetch_start_timestamp, types::ApiResponse};

#[tokio::main]
async fn main() -> Result<()> {
    println!("[main] Starting enclave service initialization...");

    let args = Args::parse();

    let state = Arc::new(RwLock::new(ApiResponse {
        enclave_sig: Vec::<u8>::new().into(),
        result_data: Vec::<u8>::new().into(),
        in_progress: true,
        error: None,
    }));

    let server_task = serve_result_api(state.clone());

    let compute_task = {
        let state = state.clone(); // capture state for updating
        async move {
            let computation = async {
                // Step 1: Load configuration
                let app_config = load_app_config_with_fallback();

                // Step 2: Initialize governance
                let contract = initialize_governance(&app_config).await?;

                // Step 3: Process proposal and tally votes
                let proposal_id_bytes = parse_proposal_id(&app_config.proposal_id)?;
                let start_timestamp = fetch_start_timestamp(proposal_id_bytes, &contract).await?;

                // Step 4: Fetch chain contexts
                let (chain_contexts, network_hash) =
                    fetch_and_display_chain_contexts(&app_config, &contract, start_timestamp).await?;

                // Step 5: Setup cryptography
                let (encryption_key, public_key) = setup_encryption(&args.derive_endpoint)?;

                let (tally, vote_hash) = tally_votes(
                    proposal_id_bytes,
                    &contract,
                    &chain_contexts,
                    &public_key,
                    &encryption_key,
                    start_timestamp,
                )
                .await?;

                // Step 6: Display tally results and fetch supply
                display_tally_results(&tally);
                let supply = fetch_and_display_supply(&chain_contexts).await?;

                // Step 7: Sign and encode results
                let signing_key =
                    fetch_signing_key(&args.derive_endpoint).context("failed to fetch signing key")?;

                let result = create_signed_result(
                    &app_config,
                    network_hash,
                    vote_hash,
                    &tally,
                    supply,
                    proposal_id_bytes,
                    signing_key,
                    start_timestamp,
                )?;
                Ok::<VoteResult, anyhow::Error>(result)
            };
    
            match computation.await {
                Ok(result) => {
                    let mut s = state.write().await;
                    *s = ApiResponse {
                        enclave_sig: result.enclave_sig.clone(),
                        result_data: result.result_data.clone(),
                        in_progress: false,
                        error: None,
                    };
                }
                Err(e) => {
                    let mut s = state.write().await;
                    *s = ApiResponse {
                        enclave_sig: Vec::<u8>::new().into(),
                        result_data: Vec::<u8>::new().into(),
                        in_progress: false,
                        error: Some(e.to_string()),
                    };
                }
            }
        
            Ok::<(), anyhow::Error>(())
        }
    };
    
    // Server keeps running, compute finishes once
    join!(server_task, compute_task);
    Ok(())
}

fn load_app_config_with_fallback() -> config::AppConfig {
    match load_app_config() {
        Ok(cfg) => {
            println!("[main] Loaded enclave config: {:?}", cfg);
            cfg
        }
        Err(e) => {
            eprintln!("[main] Failed to load enclave config: {:?}", e);
            // Return a default config or exit - preserving original logic
            std::process::exit(1);
        }
    }
}

async fn initialize_governance(
    app_config: &config::AppConfig,
) -> Result<GovernanceContract<ethers::providers::Provider<ethers::providers::Http>>> {
    let gov_config = GovernanceConfig {
        rpc_url: app_config.rpc_url.clone(),
        api_key: app_config.default_api_key.clone(),
        gov_contract: app_config.gov_contract.parse().map_err(|e| {
            eprintln!("[main] Failed to parse gov_contract: {:?}", e);
            std::process::exit(1);
        })?,
        api_keys: app_config.api_keys.clone(),
        chain_ids: app_config.chain_ids.clone(),
        rpc_indexes: app_config.rpc_index.clone(),
    };

    let provider = ethers::providers::Provider::<ethers::providers::Http>::try_from(format!(
        "{}/{}",
        gov_config.rpc_url.trim_end_matches('/'),
        gov_config.api_key
    ))
    .context("Invalid RPC URL or failed to connect")?;

    let provider = Arc::new(provider);
    let contract = GovernanceContract::new(gov_config.gov_contract, provider.clone());

    Ok(contract)
}

async fn fetch_and_display_chain_contexts(
    app_config: &config::AppConfig,
    contract: &GovernanceContract<ethers::providers::Provider<ethers::providers::Http>>,
    start_timestamp: u64
) -> Result<(Vec<governance_contract::ChainContext>, [u8; 32])> {
    let gov_config = GovernanceConfig {
        rpc_url: app_config.rpc_url.clone(),
        api_key: app_config.default_api_key.clone(),
        gov_contract: app_config.gov_contract.parse().unwrap(),
        api_keys: app_config.api_keys.clone(),
        chain_ids: app_config.chain_ids.clone(),
        rpc_indexes: app_config.rpc_index.clone(),
    };

    let (chain_contexts, network_hash) = fetch_chain_contexts(gov_config, contract, start_timestamp).await?;

    println!("[main] Loaded chain contexts from contract:");
    for ctx in &chain_contexts {
        println!(
            "  • chain_id: {} | rpc_urls: {} | token: {}",
            ctx.chain_id,
            ctx.rpc_urls.join(", "),
            ctx.token_address
        );
    }

    Ok((chain_contexts, network_hash))
}

fn setup_encryption(derive_endpoint: &str) -> Result<([u8; 32], [u8; 32])> {
    let encryption_key =
        fetch_encryption_key(derive_endpoint).context("failed to fetch encryption key")?;

    setup_libsodium()?;
    let public_key = derive_public_key(&encryption_key);

    Ok((encryption_key, public_key))
}

fn parse_proposal_id(proposal_id: &str) -> Result<[u8; 32]> {
    hex::decode(proposal_id.trim_start_matches("0x"))
        .context("failed to decode proposal_id hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("proposal_id is not 32 bytes"))
}

fn display_tally_results(
    tally: &std::collections::HashMap<types::VoteOutcome, ethers::types::U256>,
) {
    for (outcome, total_power) in tally.iter() {
        println!("{:?}: {}", outcome, total_power);
    }
}

async fn fetch_and_display_supply(
    chain_contexts: &[governance_contract::ChainContext],
) -> Result<ethers::types::U256> {
    let supply = fetch_total_supply(&chain_contexts[0])
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to fetch total supply for chain {}",
                chain_contexts[0].chain_id
            )
        })?;

    println!(
        "Total supply for chain {}: {}",
        chain_contexts[0].chain_id, supply
    );

    Ok(supply)
}

fn create_signed_result(
    app_config: &config::AppConfig,
    network_hash: [u8; 32],
    vote_hash: [u8; 32],
    tally: &std::collections::HashMap<types::VoteOutcome, ethers::types::U256>,
    supply: ethers::types::U256,
    proposal_id_bytes: [u8; 32],
    signing_key: [u8; 32],
    start_timestamp: u64,
) -> Result<VoteResult> {
    println!(
        "[main] network_hash :{}, vote_hash :{}",
        hex::encode(network_hash),
        hex::encode(vote_hash)
    );

    let gov_contract_addr: ethers::types::Address = app_config
        .gov_contract
        .parse()
        .context("Invalid contract address")?;

    let data_hash = compute_result_hash(
        gov_contract_addr,
        ethers::types::U256::from(start_timestamp),
        network_hash.into(),
        vote_hash.into(),
    );

    println!("Result hash (sha256): 0x{}", hex::encode(data_hash));

    let vote_result_tokens = serialize_vote_result(tally, supply);

    let hash = compute_vote_result_hash(
        data_hash.into(),
        proposal_id_bytes,
        vote_result_tokens.clone(),
    );

    let enclave_sig = crypto::sign_vote_result(hash, signing_key)?;

    let mut tokens = vec![ethers::abi::Token::FixedBytes(proposal_id_bytes.to_vec())];
    tokens.extend(vote_result_tokens);

    let result_data = ethers::abi::encode(&tokens);

    Ok(VoteResult {
        enclave_sig: enclave_sig.into(),
        result_data: result_data.into(),
    })
}
