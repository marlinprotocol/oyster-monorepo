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
}

pub fn load_app_config() -> Result<AppConfig> {
    // TODO: move this to init_params args only, hard coded for now
    Ok(AppConfig {
        rpc_url: read_config_file("/init-params/config/rpc_url")?,
        default_api_key: read_config_file("/init-params/secrets/default_api_key")?,
        api_keys: read_json_config("/init-params/secrets/api_keys.json")?,
        chain_ids: read_json_config("/init-params/config/chain_ids.json")?,
        rpc_index: read_json_config("/init-params/config/rpc_index.json")?,
        gov_contract: read_config_file("/init-params/config/gov_contract")?,
        proposal_id: read_config_file("/init-params/params/proposal_id")?,
    })
}

fn read_config_file(path: &str) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?
        .trim()
        .to_string()
        .pipe(Ok)
}

fn read_json_config<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read JSON config file: {}", path))?;

    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON config file: {}", path))
}

trait Pipe<T> {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U;
}

impl<T> Pipe<T> for T {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U,
    {
        f(self)
    }
}
