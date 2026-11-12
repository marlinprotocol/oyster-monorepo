use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use reqwest::Url;

pub async fn get_latest_block_number(http_rpc_url: &String) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    http_rpc_client
        .get_block_number()
        .await
        .context("Failed to get a response from the rpc server")
}

pub fn get_byte_slice(num: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = num;
    bytes
}
