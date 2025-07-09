use std::io::ErrorKind;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::BlockTransactionsKind;
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Context, Error, Result};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::model::{SecretManagerContract, SecretMetadata};

pub fn verify_rpc_url(rpc_url: &str) -> Result<()> {
    let url = Url::parse(rpc_url).context(format!("Failed to parse the RPC {:?}", rpc_url))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow!(
            "Invalid RPC URL: {:?}. URL must start with http or https",
            rpc_url
        ));
    }
    Ok(())
}

// Create and write secret to a file location asynchronously with retries
pub async fn create_and_populate_file(path: String, data: &[u8]) -> Result<()> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            // Create or open the file at the specified path
            let mut file = File::create(&path).await?;

            // Write the secret data as bytes to the file
            file.write_all(data).await?;

            Ok::<(), Error>(())
        },
    )
    .await?)
}

// Open and read secret from the file location asynchronously with retries
pub async fn open_and_read_file(path: String) -> Result<Vec<u8>> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            // Open the file at the provided location
            let mut file = File::open(&path).await?;

            // Read and copy the file contents as bytes
            let mut secret = Vec::new();
            file.read_to_end(&mut secret).await?;

            Ok::<Vec<u8>, Error>(secret)
        },
    )
    .await?)
}

// Delete a secret at a file location asynchronously if it exists there with retries
pub async fn check_and_delete_file(path: String) -> Result<()> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            match fs::remove_file(&path).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    // No need to delete if the file doesn't exist
                    if err.kind() == ErrorKind::NotFound {
                        return Ok(());
                    }

                    Err(err)
                }
            }
        },
    )
    .await?)
}

// Conversion function for B256 type to Address type
pub fn b256_to_address(hash: B256) -> Address {
    Address::from_slice(&hash.0[12..]) // Extract last 20 bytes
}

pub fn timestamp_to_instant(timestamp: u64) -> Result<Instant> {
    // Get the SystemTime for the given timestamp
    let time = UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(timestamp))
        .ok_or_else(|| anyhow!("Invalid timestamp value"))?;

    // Get the current SystemTime and calculate the difference
    let now = SystemTime::now();
    let instant_now = Instant::now();
    match time.duration_since(now) {
        Ok(duration_from_now) => Ok(instant_now + duration_from_now),
        Err(duration_since_past) => Ok(instant_now - duration_since_past.duration()),
    }
}

pub async fn get_latest_block_number(http_rpc_url: &String) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    http_rpc_client
        .get_block_number()
        .await
        .context("Failed to get a response from the rpc server")
}

pub async fn get_block_timestamp(http_rpc_url: &String, block_number: u64) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    let Some(block_response) = http_rpc_client
        .get_block(block_number.into(), BlockTransactionsKind::Hashes)
        .await
        .context("Failed to get block response from rpc server")?
    else {
        return Err(anyhow!(
            "Timestamp not available for the block number: {}",
            block_number
        ));
    };

    Ok(block_response.header.timestamp)
}

pub async fn get_secret_metadata(
    http_rpc_url: &String,
    secret_manager_contract_addr: Address,
    secret_id: U256,
) -> Result<SecretMetadata> {
    let http_rpc_client = ProviderBuilder::new()
        .on_http(Url::parse(http_rpc_url).context("Failed to parse the RPC URL")?);
    let secret_manager_contract =
        SecretManagerContract::new(secret_manager_contract_addr, http_rpc_client);

    let user_storage = secret_manager_contract
        .userStorage(secret_id)
        .call()
        .await
        .context("Failed to get a response from the RPC server")?;

    Ok(SecretMetadata {
        owner: user_storage.owner,
        size_limit: user_storage.sizeLimit,
        end_timestamp: user_storage.endTimestamp,
    })
}
