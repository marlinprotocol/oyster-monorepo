use anyhow::{Context, Result};
use std::fs;

#[derive(Debug)]
pub struct AppConfig {
    pub rpc_url: String,
    pub default_api_key: String,
    pub api_keys: Vec<String>,
    pub chain_ids: Vec<u64>,
    pub rpc_index: Vec<usize>,
    pub gov_contract: String,
    pub proposal_id: String,
    pub data_hash: String,
    pub start_ts: u64,
}

pub fn load_app_config() -> Result<AppConfig> {
    Ok(AppConfig {
        rpc_url: fs::read_to_string("/init-params/config/rpc_url")?
            .trim()
            .to_string(),

        default_api_key: fs::read_to_string("/init-params/secrets/default_api_key")?
            .trim()
            .to_string(),

        api_keys: serde_json::from_str(&fs::read_to_string("/init-params/secrets/api_keys.json")?)?,

        chain_ids: serde_json::from_str(&fs::read_to_string(
            "/init-params/config/chain_ids.json",
        )?)?,

        rpc_index: serde_json::from_str(&fs::read_to_string(
            "/init-params/config/rpc_index.json",
        )?)?,

        gov_contract: fs::read_to_string("/init-params/config/gov_contract")?
            .trim()
            .to_string(),

        proposal_id: fs::read_to_string("/init-params/params/proposal_id")?
            .trim()
            .to_string(),

        data_hash: fs::read_to_string("/init-params/params/data_hash")?
            .trim()
            .to_string(),

        start_ts: fs::read_to_string("/init-params/params/start_ts")?
            .trim()
            .parse()
            .context("Invalid start_ts format (expected u64)")?,
    })
}
