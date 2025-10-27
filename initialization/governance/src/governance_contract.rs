//! Governance contract interaction module.

use anyhow::{Context, Result};
use ethers::{
    contract::abigen,
    providers::{Http, Provider},
    types::{Address, H160, U256},
};
use std::{collections::HashMap, sync::Arc};

use crate::crypto::decrypt_vote;
use crate::hash::{compute_chain_hash, compute_network_hash};
use crate::types::VoteOutcome;

// ------------------------
// Configuration Structs
// ------------------------

#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub rpc_url: String,
    pub api_key: String,
    pub gov_contract: Address,
    pub chain_ids: Vec<u64>,
    pub rpc_indexes: Vec<usize>,
    pub api_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ChainContext {
    pub chain_id: u64,
    pub rpc_urls: Vec<String>,
    pub token_address: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TokenNetworkConfig {
    pub chain_hash: [u8; 32],
    pub token_address: Address,
    pub rpc_urls: Vec<String>,
}

// ------------------------
// Contract Bindings
// ------------------------

abigen!(
    GovernanceContract,
    "src/abis/governance_contract_abi.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(ERC20, "src/abis/erc20_abi.json");

// ------------------------
// Main Contract Operations
// ------------------------

pub async fn fetch_chain_contexts(
    config: GovernanceConfig,
    contract: &GovernanceContract<Provider<Http>>,
    start_timestamp: u64
) -> Result<(Vec<ChainContext>, [u8; 32])> {

    let provider = contract.client();
    let snapshot_block =
    match find_snapshot_block(provider.clone(), start_timestamp).await {
        Ok(b) => b,
        Err(e) => anyhow::bail!("Failed to find snapshot block for fetching chain context: {}", e),
    };

    let block_id = ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(
        snapshot_block.as_u64().into(),
    ));

    let (chain_ids_list, raw_configs): (Vec<U256>, Vec<NetworkConfig>) = contract
        .get_all_network_configs()
        .block(block_id)
        .call()
        .await
        .context("failed to fetch network list")?;

    let network_config_list: Vec<(String, H160, Vec<String>)> = raw_configs
        .into_iter()
        .map(|config| {
            let id_str = format!("0x{}", hex::encode(config.chain_hash));
            (id_str, config.token_address, config.rpc_urls)
        })
        .collect();

    if chain_ids_list.len() != network_config_list.len() {
        anyhow::bail!("Mismatch between chain_ids and network_config_list");
    }
    if config.chain_ids.len() != config.rpc_indexes.len()
        || config.chain_ids.len() != config.api_keys.len()
    {
        anyhow::bail!("Length mismatch in chain_ids, rpc_indexes, or api_keys from init params");
    }

    let mut contexts = vec![];
    let mut chain_hashes = vec![];

    for (i, &chain_id) in config.chain_ids.iter().enumerate() {
        let index = chain_ids_list
            .iter()
            .position(|&id| id == chain_id.into())
            .ok_or_else(|| anyhow::anyhow!("Chain ID {} not found in getNetworkList", chain_id))?;

        let network_cfg = &network_config_list[index];
        let rpc_urls = &network_cfg.2;

        let rpc_index = config.rpc_indexes[i];
        let key = config.api_keys[i].clone();

        let raw_base_url = rpc_urls.get(rpc_index).ok_or_else(|| {
            anyhow::anyhow!(
                "Index {} out of bounds for chain_id {}",
                rpc_index,
                chain_id
            )
        })?;

        let full_url = format!("{}/{}", raw_base_url.trim_end_matches('/'), key);
        let chain_hash = compute_chain_hash(chain_id, &rpc_urls);

        println!(
            "chain_id: {} | rpc_url: {:?}\n  chainHash = 0x{}\n",
            chain_id,
            rpc_urls,
            hex::encode(chain_hash)
        );

        chain_hashes.push(chain_hash);
        contexts.push(ChainContext {
            chain_id,
            rpc_urls: vec![full_url],
            token_address: network_cfg.1,
        });
    }

    let network_hash = compute_network_hash(chain_hashes);
    println!("✅ Final NetworkHash = 0x{}", hex::encode(network_hash));

    Ok((contexts, network_hash))
}

pub async fn fetch_start_timestamp(
    proposal_id: [u8; 32],
    contract: &GovernanceContract<Provider<Http>>,
) -> Result<u64> {
    let info = contract
        .get_proposal_time_info(proposal_id)
        .call()
        .await
        .context("Failed to fetch proposal time info")?;
    Ok(info.proposed_timestamp.as_u64())
}

pub async fn tally_votes(
    proposal_id: [u8; 32],
    contract: &GovernanceContract<Provider<Http>>,
    chains: &[ChainContext],
    pk: &[u8; 32],
    sk: &[u8; 32],
    start_timestamp: u64,
) -> Result<(HashMap<VoteOutcome, U256>, [u8; 32])> {
    let mut results: HashMap<VoteOutcome, U256> = HashMap::new();
    let (votes, vote_hash) = fetch_votes(contract, proposal_id).await?;

    println!(
        "Fetched {} votes for proposal {}",
        votes.len(),
        hex::encode(proposal_id)
    );

    for (voter, encrypted) in votes {
        let outcome = decrypt_vote(&encrypted, pk, sk)?;
        let mut total_power = U256::zero();

        for chain in chains {
            for url in &chain.rpc_urls {
                let provider = match Provider::<Http>::try_from(url) {
                    Ok(p) => p,
                    Err(e) => anyhow::bail!("Failed to connect to rpc provider: {}", e),
                };
                let client = Arc::new(provider);
                let token = ERC20::new(chain.token_address, client.clone());

                let snapshot_block =
                    match find_snapshot_block(client.clone(), start_timestamp).await {
                        Ok(b) => b,
                        Err(e) => anyhow::bail!("Failed to find snapshot block for voter balance: {}", e),
                    };

                let block_id = ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(
                    snapshot_block.as_u64().into(),
                ));
                match token
                    .method::<_, U256>("balanceOf", voter)
                    .unwrap()
                    .block(block_id)
                    .call()
                    .await
                {
                    Ok(balance) => {
                        total_power += balance;
                        break;
                    }
                    Err(e) => anyhow::bail!("Failed to get voter balance: {} {}", voter, e),
                }
            }
        }

        *results.entry(outcome).or_insert(U256::zero()) += total_power;
    }

    Ok((results, vote_hash))
}

pub async fn fetch_total_supply(chain: &ChainContext) -> Option<U256> {
    for url in &chain.rpc_urls {
        if let Ok(provider) = Provider::<Http>::try_from(url) {
            let client = Arc::new(provider);
            let token = ERC20::new(chain.token_address, client);
            if let Ok(supply) = token
                .method::<_, U256>("totalSupply", ())
                .unwrap()
                .call()
                .await
            {
                return Some(supply);
            }
        }
    }
    None
}

async fn fetch_votes(
    contract: &GovernanceContract<Provider<Http>>,
    proposal_id: [u8; 32],
) -> Result<(HashMap<Address, Vec<u8>>, [u8; 32])> {
    let vote_count = contract
        .get_vote_count(proposal_id)
        .call()
        .await
        .context("Failed to fetch vote count")?;

    let mut votes = HashMap::new();
    let mut vote_hash = [0u8; 32];

    for i in 0..vote_count.as_u64() {
        let (voter, decision) = contract
            .get_vote_info(proposal_id, i.into())
            .call()
            .await
            .with_context(|| format!("Failed to fetch vote #{}", i))?;
        vote_hash = crate::hash::update_vote_hash(vote_hash, &decision);

        votes.insert(voter, decision.to_vec());
        println!(
            "Fetched vote {}: voter = {}, decision = {}",
            i,
            hex::encode(voter),
            hex::encode(&decision)
        );
    }

    Ok((votes, vote_hash))
}

async fn find_snapshot_block<M: ethers::providers::Middleware + 'static>(
    provider: Arc<M>,
    target_ts: u64,
) -> Result<U256> {
    let latest = provider
        .get_block(ethers::types::BlockNumber::Latest)
        .await?
        .ok_or_else(|| anyhow::anyhow!("No latest block"))?;

    let mut low = U256::zero();
    let mut high = U256::from(
        latest
            .number
            .ok_or_else(|| anyhow::anyhow!("Missing block number"))?
            .as_u64(),
    );

    while low < high {
        let mid = (low + high) / 2;
        let block = provider
            .get_block(mid.as_u64())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", mid))?;
        let ts = U256::from(block.timestamp.as_u64());
        let target = U256::from(target_ts);

        if ts < target {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    Ok(low)
}
