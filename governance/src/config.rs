use alloy::{
    consensus::BlockHeader,
    network::{BlockResponse, Network},
    primitives::{Address, U256},
    providers::{Provider, RootProvider},
};
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::{collections::HashMap, fs};
use url::Url;

use crate::{
    delegation::Delegation, governance::Governance, governance_enclave::GovernanceEnclave,
};

#[derive(Deserialize)]
pub struct GovernanceConfig {
    pub governance_contract: String,
    pub governance_enclave: String,
    pub gov_chain_rpc_url: String,
    pub other_rpc_urls: HashMap<String, String>,
    pub init_dirty_key: String,
}

pub fn get_governance<N: Network>() -> Result<Governance<N>> {
    let cfg = get_config()?;

    // validate address early for a nicer error
    let _addr: Address = cfg
        .governance_contract
        .parse()
        .with_context(|| format!("invalid governance_contract address"))?;

    // build the client
    let governance: Governance<N> =
        Governance::new(&cfg.gov_chain_rpc_url, &cfg.governance_contract)?;
    Ok(governance)
}

pub fn get_governance_enclave<N: Network>() -> Result<GovernanceEnclave<N>> {
    let cfg = get_config()?;

    // validate address early for a nicer error
    let _addr: Address = cfg
        .governance_enclave
        .parse()
        .with_context(|| format!("invalid governance_enclave address"))?;

    // build the client
    let governance_enclave: GovernanceEnclave<N> =
        GovernanceEnclave::new(&cfg.gov_chain_rpc_url, &cfg.governance_enclave)?;
    Ok(governance_enclave)
}

pub fn get_rpc_url(chain_id: U256) -> Result<String> {
    let cfg = get_config().context("loading config")?;

    // find RPC URL for given chain_id
    let cid = chain_id.to_string();
    println!("cid: {}", cid);
    let rpc_url = cfg
        .other_rpc_urls
        .get(&cid)
        .ok_or_else(|| anyhow!("no RPC URL found for chain_id {}", cid))?;

    Ok(rpc_url.clone())
}

pub fn get_governanace_delegation<N: Network>(
    chain_id: U256,
    delegation_address: &str,
) -> Result<Delegation<N>> {
    // load config (your earlier get_config())
    let cfg = get_config().context("loading config")?;

    // parse the delegation address early
    let _addr: Address = delegation_address
        .parse()
        .context("invalid delegation_address address")?;

    // find RPC URL for given chain_id
    let cid = chain_id.to_string();
    println!("cid: {}", cid);
    let rpc_url = cfg
        .other_rpc_urls
        .get(&cid)
        .ok_or_else(|| anyhow!("no RPC URL found for chain_id {}", cid))?;

    // Validate the URL string
    let url = Url::parse(rpc_url)
        .with_context(|| format!("invalid RPC URL '{}' for chain {}", rpc_url, cid))?;

    // build the client
    let delegation: Delegation<N> = Delegation::new(url.as_str(), delegation_address)
        .context("failed to create Delegation client")?;

    Ok(delegation)
}

pub fn get_config() -> Result<GovernanceConfig> {
    let candidates = ["./config/config.json", "/config/config.json"];

    // find the first readable config
    let (path, contents) = candidates
        .iter()
        .find_map(|p| fs::read_to_string(p).ok().map(|s| (*p, s)))
        .ok_or_else(|| anyhow!("config.json not found in ./config or /config"))?;

    // parse and validate
    let cfg: GovernanceConfig =
        serde_json::from_str(&contents).with_context(|| format!("parse failed for {path}"))?;
    Ok(cfg)
}

pub async fn latest_block<N: Network>(chain_rpc_url: &str) -> Result<u64> {
    let url = Url::parse(chain_rpc_url)?;

    let provider = RootProvider::<N>::new_http(url);
    let latest_num = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("get_block_number failed: {e}"))?;

    Ok(latest_num)
}

pub async fn find_block_by_timestamp<N: Network>(
    chain_rpc_url: &str,
    target_ts: u64,
) -> Result<u64> {
    let url = Url::parse(chain_rpc_url)?;
    let provider = RootProvider::<N>::new_http(url);

    // 1) load latest block number
    let latest_num = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("get_block_number failed: {e}"))?;
    let latest_num: u64 = latest_num
        .try_into()
        .map_err(|_| anyhow!("latest block number too large"))?;

    // 2) fetch earliest timestamp (block 0 or 1)
    let low_num = 0u64;
    let low_block = provider
        .get_block_by_number(low_num.into())
        .await
        .map_err(|e| anyhow!("get_block({low_num}) failed: {e}"))?
        .ok_or_else(|| anyhow!("block {low_num} not found"))?;
    let low_ts = low_block.header().timestamp();

    // 3) fetch high timestamp
    let high_block = provider
        .get_block_by_number(latest_num.into())
        .await
        .map_err(|e| anyhow!("get_block({latest_num}) failed: {e}"))?
        .ok_or_else(|| anyhow!("block {latest_num} not found"))?;
    let high_ts = high_block.header().timestamp();

    // edge cases
    if target_ts <= low_ts {
        return Ok(low_num);
    }
    if target_ts >= high_ts {
        return Ok(latest_num);
    }

    // 4) binary search between low_num and latest_num
    binary_search_block(&provider, target_ts, low_num, latest_num).await
}

async fn binary_search_block<N: Network>(
    provider: &RootProvider<N>,
    target_ts: u64,
    mut low: u64,
    mut high: u64,
) -> Result<u64> {
    while low + 1 < high {
        let mid = low + (high - low) / 2;
        let block = provider
            .get_block_by_number(mid.into())
            .await
            .map_err(|e| anyhow!("get_block({mid}) failed: {e}"))?
            .ok_or_else(|| anyhow!("block {mid} not found"))?;
        let ts = block.header().timestamp();

        if ts == target_ts {
            return Ok(mid);
        } else if ts < target_ts {
            low = mid;
        } else {
            high = mid;
        }
    }
    // at this point, high = low + 1, return low as the closest <= target_ts
    Ok(low)
}
