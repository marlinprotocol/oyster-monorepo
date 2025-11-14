use alloy::{
    consensus::BlockHeader,
    network::{BlockResponse, Network},
    primitives::{Address, U256},
    providers::{Provider, RootProvider},
};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};
use url::Url;

use crate::{
    delegation::Delegation, governance::Governance, governance_enclave::GovernanceEnclave,
};

pub const GOVERNANCE: &str = "0x5F5e03D26419f8fa106Dea7336B4872DC3a7AE48";
pub const GOVERNANCE_ENCLAVE: &str = "0xf6EF8A444c47ab142B33D0EEb60c60050916d64F";
pub const GOV_CHAIN_BASE_RPC: &str = "https://arbitrum-sepolia.core.chainstack.com/";

#[derive(Deserialize)]
pub struct GovernanceConfig {
    pub governance_contract: String,
    pub governance_enclave: String,
    pub gov_chain_apikey: String,
    pub rpc_apikeys: HashMap<String, String>,
}

/// Constructs a new instance of governance contract
///
/// # Examples
/// ```
/// use governance::config::get_governance;
/// use alloy::network::Ethereum;
///
/// let governance = get_governance::<Ethereum>();
///
/// ```
pub fn get_governance<N: Network>() -> Result<Governance<N>> {
    let cfg = get_config()?;

    // validate address early for a nicer error
    let _addr: Address = cfg
        .governance_contract
        .parse()
        .with_context(|| format!("invalid governance_contract address"))?;

    let _envc: Address = cfg
        .governance_enclave
        .parse()
        .with_context(|| format!("invalid governance_enclave address"))?;

    // build the client
    let governance: Governance<N> = Governance::new(
        &create_gov_chain_rpc_url()?,
        &cfg.governance_contract,
        &cfg.governance_enclave,
    )?;
    Ok(governance)
}

/// Constructs a new instance of governance enclave contract
///
/// # Examples
/// ```
/// use governance::config::get_governance_enclave;
/// use alloy::network::Ethereum;
///
/// let governance_enclave = get_governance_enclave::<Ethereum>();
///
/// ```
pub fn get_governance_enclave<N: Network>() -> Result<GovernanceEnclave<N>> {
    let cfg = get_config()?;

    // validate address early for a nicer error
    let _addr: Address = cfg
        .governance_enclave
        .parse()
        .with_context(|| format!("invalid governance_enclave address"))?;

    // build the client
    let governance_enclave: GovernanceEnclave<N> =
        GovernanceEnclave::new(&create_gov_chain_rpc_url()?, &cfg.governance_enclave)?;
    Ok(governance_enclave)
}

/// Returns governance chain rpc url
///
/// # Examples
/// ```
/// use governance::config::create_gov_chain_rpc_url;
///
/// let rpc_url = create_gov_chain_rpc_url();
///
/// ```
pub fn create_gov_chain_rpc_url() -> Result<String> {
    let rpc_apikey = get_gov_chain_rpc_apikey()?;
    let rpc_url = format!("{}{}", GOV_CHAIN_BASE_RPC, rpc_apikey);

    let url = Url::parse(rpc_url.as_ref())
        .with_context(|| format!("invalid GOVERNANCE CHAIN URL '{}'", rpc_url))?;

    Ok(url.as_str().to_string())
}

/// Returns governance chain rpc apikey
///
/// # Examples
/// ```
/// use governance::config::get_gov_chain_rpc_apikey;
///
/// let apikey = get_gov_chain_rpc_apikey();
///
/// ```
pub fn get_gov_chain_rpc_apikey() -> Result<String> {
    let cfg = get_config().context("loading config")?;
    Ok(cfg.gov_chain_apikey)
}

/// Returns other chain rpc apikey
///
/// # Examples
/// ```
/// use alloy::primitives::U256;
/// use governance::config::get_rpc_apikey;
/// let chain_id = U256::from(1);
/// let apikey = get_rpc_apikey(chain_id);
///
/// ```
pub fn get_rpc_apikey(chain_id: U256) -> Result<String> {
    let cfg = get_config().context("loading config")?;

    // find RPC URL for given chain_id
    let cid = chain_id.to_string();
    let rpc_apikey = cfg
        .rpc_apikeys
        .get(&cid)
        .ok_or_else(|| anyhow!("no RPC apikey found for chain_id {}", cid))?;
    log::debug!("cid: {} rpc_apikey: {}", cid, rpc_apikey);

    Ok(rpc_apikey.clone())
}

/// Returns other chain rpc url
///
/// # Examples
/// ```
/// use alloy::primitives::U256;
/// use governance::config::create_rpc_url;
/// let chain_id = U256::from(1);
/// let base_url = "base rpc";
/// let rpc_url = create_rpc_url(base_url, chain_id);
///
/// ```
pub fn create_rpc_url(base_url: &str, chain_id: U256) -> Result<String> {
    let cid = chain_id.to_string();
    let rpc_apikey = get_rpc_apikey(chain_id)?;
    log::debug!("cid: {} rpc_apikey: {}", cid, rpc_apikey);

    let rpc_url = format!("{}{}", base_url, rpc_apikey);

    let url = Url::parse(rpc_url.as_ref())
        .with_context(|| format!("invalid RPC URL '{}' for chain {}", rpc_url, cid))?;

    Ok(url.as_str().to_string())
}

/// Constructs a new instance of delegation contract
///
/// # Examples
/// ```
/// use governance::config::get_governanace_delegation;
/// use alloy::network::Ethereum;
/// use alloy::primitives::{U256, Address};
/// let chain_id = U256::from(1);
/// let base_url = "base rpc";
/// let delegation_contract_address = "0xabcdef01abcdef01abcdef01abcdef01abcdef01";
///
/// let delegation_contract = get_governanace_delegation::<Ethereum>(chain_id, base_url, delegation_contract_address);
///
/// ```
pub fn get_governanace_delegation<N: Network>(
    chain_id: U256,
    base_url: &str,
    delegation_address: &str,
) -> Result<Delegation<N>> {
    // parse the delegation address early
    let _addr: Address = delegation_address
        .parse()
        .context("invalid delegation_address address")?;

    let url = create_rpc_url(base_url, chain_id)?;

    // build the client
    let delegation: Delegation<N> = Delegation::new(url.as_str(), delegation_address)
        .context("failed to create Delegation client")?;

    Ok(delegation)
}

/// Returns governance config
///
/// # Examples
/// ```
/// use governance::config::get_config;
///
/// let config = get_config();
///
/// ```
pub fn get_config() -> Result<GovernanceConfig> {
    let candidates = ["./config/config.json", "/config/config.json"];

    // find the first readable config
    let (path, contents) = candidates
        .iter()
        .find_map(|p| fs::read_to_string(p).ok().map(|s| (*p, s)))
        .ok_or_else(|| anyhow!("config.json not found in ./config or /config"))?;

    #[derive(Serialize, Deserialize)]
    struct Base {
        gov_chain_apikey: String,
        rpc_apikeys: HashMap<String, String>,
    }
    // parse and validate
    let base_cfg: Base =
        serde_json::from_str(&contents).with_context(|| format!("parse failed for {path}"))?;

    let cfg = GovernanceConfig {
        governance_contract: GOVERNANCE.to_string(),
        governance_enclave: GOVERNANCE_ENCLAVE.to_string(),
        gov_chain_apikey: base_cfg.gov_chain_apikey,
        rpc_apikeys: base_cfg.rpc_apikeys,
    };
    Ok(cfg)
}

/// Returns latest block on chain
///
/// # Examples
/// ```
/// use governance::config::latest_block;
/// use alloy::network::Ethereum;
/// let chain_rpc_url = "chain_rpc_url rpc";
/// let block = latest_block::<Ethereum>(chain_rpc_url);
///
/// ```
pub async fn latest_block<N: Network>(chain_rpc_url: &str) -> Result<u64> {
    let url = Url::parse(chain_rpc_url)?;

    let provider = RootProvider::<N>::new_http(url);
    let latest_num = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("get_block_number failed: {e}"))?;

    Ok(latest_num)
}

/// Find the block number closest to the given timestamp
///
/// # Examples
/// ```
/// use governance::config::find_block_by_timestamp;
/// use alloy::network::Ethereum;
/// let chain_rpc_url = "chain_rpc_url rpc";
/// let target_ts = 1234;
/// let block = find_block_by_timestamp::<Ethereum>(chain_rpc_url, target_ts);
///
/// ```
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
    low: u64,
    high: u64, // inclusive upper bound expected by caller
) -> Result<u64> {
    // Convert to [low, high+1) to do a lower_bound (first ts >= target_ts)
    let mut l = low;
    let mut r = high + 1;

    while l < r {
        let mid = l + (r - l) / 2;
        let ts = block_ts(provider, mid).await?;
        if ts < target_ts {
            l = mid + 1;
        } else {
            // ts >= target_ts → shrink right, ensuring we land on the first >=
            r = mid;
        }
    }

    // l is the first index with ts >= target_ts, or high+1 if all ts < target_ts
    if l <= high {
        let ts_l = block_ts(provider, l).await?;
        if ts_l == target_ts {
            // This is the earliest block with the exact timestamp.
            return Ok(l);
        }
    }

    // No exact match: return the floor (largest block with ts < target_ts).
    // If even genesis is >= target_ts, clamp to low.
    if l == 0 { Ok(low) } else { Ok(l - 1) }
}

async fn block_ts<N: Network>(provider: &RootProvider<N>, n: u64) -> Result<u64> {
    let b = provider
        .get_block_by_number(n.into())
        .await
        .map_err(|e| anyhow!("get_block({n}) failed: {e}"))?
        .ok_or_else(|| anyhow!("block {n} not found"))?;
    Ok(b.header().timestamp())
}
