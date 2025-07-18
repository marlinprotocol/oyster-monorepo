use anyhow::{Context, Result};
use ethers::{
    contract::abigen,
    providers::{Http, Middleware, Provider},
    types::{Address, BlockId, BlockNumber, H160, U256},
};
use libsodium_sys::{crypto_box_SEALBYTES, crypto_box_seal_open, sodium_init};
use std::{collections::HashMap, sync::Arc};

// ------------------------
// Structs
// ------------------------

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

abigen!(ERC20, "src/abis/erc20_abi.json",);

// ------------------------
// Vote Outcome Enum
// ------------------------

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum VoteOutcome {
    Pending = 0,
    Passed = 1,
    Failed = 2,
    Vetoed = 3,
}

impl TryFrom<u8> for VoteOutcome {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(VoteOutcome::Pending),
            1 => Ok(VoteOutcome::Passed),
            2 => Ok(VoteOutcome::Failed),
            3 => Ok(VoteOutcome::Vetoed),
            _ => Err(anyhow::anyhow!("Invalid vote outcome byte: {}", value)),
        }
    }
}

// ------------------------
// Fetcher Logic
// ------------------------

pub async fn fetch_chain_contexts(
    config: GovernanceConfig,
    contract: &GovernanceContract<Provider<Http>>,
) -> Result<Vec<ChainContext>> {

    // TODO : Fetch these networkconfig and chain_ids for start timestamp (don't know how to do this yet)
    let (chain_ids_list, raw_configs): (Vec<U256>, Vec<NetworkConfig>) = contract
        .get_network_list()
        .call()
        .await
        .context("failed to fetch network list")?;

    // Convert raw_configs (Vec<NetworkConfig>) to the expected Rust types
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

        contexts.push(ChainContext {
            chain_id,
            rpc_urls: vec![full_url],
            token_address: network_cfg.1,
        });
    }

    Ok(contexts)
}

pub async fn fetch_votes(
    contract: &GovernanceContract<Provider<Http>>,
    proposal_id: [u8; 32],
) -> Result<Vec<(Address, Vec<u8>)>> {
    let vote_count = contract
        .get_vote_count(proposal_id)
        .call()
        .await
        .context("Failed to fetch vote count")?;

    let mut votes = vec![];

    for i in 0..vote_count.as_u64() {
        let (voter, decision) = contract
            .get_vote_info(proposal_id, i.into())
            .call()
            .await
            .with_context(|| format!("Failed to fetch vote #{}", i))?;
        votes.push((voter, decision.to_vec()));
    }

    Ok(votes)
}

pub fn decrypt_vote(encrypted: &[u8], pk: &[u8; 32], sk: &[u8; 32]) -> Result<VoteOutcome> {
    // TODO: make sure no memory leaks if possible
    unsafe {
        sodium_init(); // required before using sodium APIs
    }

    if encrypted.len() < crypto_box_SEALBYTES as usize {
        anyhow::bail!(
            "Encrypted vote too short: got {}, expected at least {}",
            encrypted.len(),
            crypto_box_SEALBYTES
        );
    }

    let mut decrypted = vec![0u8; encrypted.len() - crypto_box_SEALBYTES as usize];

    let status = unsafe {
        crypto_box_seal_open(
            decrypted.as_mut_ptr(),
            encrypted.as_ptr(),
            encrypted.len() as u64,
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };

    if status != 0 {
        anyhow::bail!("Failed to decrypt vote using enclave key");
    }

    let outcome_byte = *decrypted
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("Invalid decrypted vote"))?;
    Ok(VoteOutcome::try_from(outcome_byte)?)
}

// TODO: Look for a more efficient way to find the snapshot block
async fn find_snapshot_block<M: Middleware + 'static>(
    provider: Arc<M>,
    target_ts: u64,
) -> Result<U256> {
    let latest = provider
        .get_block(BlockNumber::Latest)
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

pub async fn tally_votes(
    proposal_id: [u8; 32],
    contract: &GovernanceContract<Provider<Http>>,
    chains: &[ChainContext],
    pk: &[u8; 32],
    sk: &[u8; 32],
    start_timestamp: u64,
) -> Result<HashMap<VoteOutcome, U256>> {
    let mut results: HashMap<VoteOutcome, U256> = HashMap::new();
    let votes = fetch_votes(contract, proposal_id).await?;

    // TODO : optimization
    // This is a sequential loop for simplicity
    for (voter, encrypted) in votes {
        // TODO: better to do decryption while fetching votes to simplify this logic
        let outcome = decrypt_vote(&encrypted, pk, sk)?;
        let mut total_power = U256::zero();

        for chain in chains {
            for url in &chain.rpc_urls {
                let provider = match Provider::<Http>::try_from(url) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let client = Arc::new(provider);
                let token = ERC20::new(chain.token_address, client.clone());

                let snapshot_block =
                    match find_snapshot_block(client.clone(), start_timestamp).await {
                        Ok(b) => b,
                        Err(_) => continue,
                    };

                let block_id = BlockId::Number(BlockNumber::Number(snapshot_block.as_u64().into()));
                match token
                    .method::<_, U256>("balanceOf", voter)?
                    .block(block_id)
                    .call()
                    .await
                {
                    Ok(balance) => {
                        total_power += balance;
                        // TODO: check for multiple rpcs for each chain
                        // If it is consistent, break
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        *results.entry(outcome).or_insert(U256::zero()) += total_power;
    }

    Ok(results)
}

pub async fn fetch_total_supply(chain: &ChainContext) -> Option<U256> {
    for url in &chain.rpc_urls {
        if let Ok(provider) = Provider::<Http>::try_from(url) {
            let client = Arc::new(provider);
            let token = ERC20::new(chain.token_address, client);
            if let Ok(supply) = token.method::<_, U256>("totalSupply", ()).unwrap().call().await {
                return Some(supply);
            }
        }
    }
    None
}