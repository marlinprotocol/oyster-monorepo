use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::eth::Log;
use anyhow::{anyhow, Context, Result};
use indexer_framework::LogsProvider;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use sui_rpc::client::{Client, HeadersInterceptor, ResponseExt};
use sui_rpc::field::FieldMask;
use sui_rpc::proto::sui::rpc::v2::{Checkpoint, GetCheckpointRequest};
use sui_sdk_types::CheckpointData;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::constants::{DEFAULT_FETCH_CONCURRENCY, DEFAULT_REQUEST_TIMEOUT, GRPC_AUTH_TOKEN};

#[derive(Clone)]
pub struct SuiProvider {
    pub remote_checkpoint_url: String,
    pub grpc_url: String,
    pub rpc_username: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_token: Option<String>,
    pub package_id: String,
}

/// Intermediate representation of a Sui log/event
#[derive(Debug, Clone)]
pub struct SuiLog {
    pub type_: String,
    pub contents: Vec<u8>,
    pub tx_digest: String,
}

impl SuiProvider {
    /// Creates a gRPC client with appropriate authentication headers
    fn get_client(&self) -> Result<Client> {
        if let Some(username) = &self.rpc_username {
            let mut headers = HeadersInterceptor::default();
            headers.basic_auth(username, self.rpc_password.clone());

            Ok(Client::new(&self.grpc_url)?.with_headers(headers))
        } else if let Some(token) = &self.rpc_token {
            let mut headers = HeadersInterceptor::default();
            headers
                .headers_mut()
                .insert(GRPC_AUTH_TOKEN, token.parse()?);

            Ok(Client::new(&self.grpc_url)?.with_headers(headers))
        } else {
            Ok(Client::new(&self.grpc_url)?)
        }
    }

    /// Fetches the latest checkpoint sequence number
    async fn fetch_latest_checkpoint_async(&self) -> Result<u64> {
        let provider = self
            .get_client()
            .context("Failed to initialize gRPC client from the provided url and credentials")?;

        let current_checkpoint = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                async move {
                    timeout(
                        DEFAULT_REQUEST_TIMEOUT,
                        provider
                            .ledger_client()
                            .get_checkpoint(GetCheckpointRequest::latest()),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching latest checkpoint")?
        .context("Request failed for fetching latest checkpoint")?;

        Ok(current_checkpoint
            .into_inner()
            .checkpoint()
            .sequence_number())
    }

    /// Fetches the timestamp for a specific checkpoint
    async fn fetch_checkpoint_timestamp_async(&self, checkpoint_number: u64) -> Result<u64> {
        let provider = self
            .get_client()
            .context("Failed to initialize gRPC client from the provided url and credentials")?;

        let checkpoint = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                async move {
                    timeout(
                        DEFAULT_REQUEST_TIMEOUT,
                        provider
                            .ledger_client()
                            .get_checkpoint(GetCheckpointRequest::by_sequence_number(
                                checkpoint_number,
                            )),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching checkpoint timestamp")?
        .context("Request failed for fetching checkpoint timestamp")?;

        // Get timestamp from response headers - Sui timestamps are in milliseconds, convert to seconds
        let timestamp_ms = checkpoint.timestamp_ms().unwrap_or(0);
        Ok(timestamp_ms / 1000)
    }

    /// Fetches logs/events for a range of checkpoints
    async fn fetch_logs_async(&self, start_block: u64, end_block: u64) -> Result<Vec<Log>> {
        let provider = self
            .get_client()
            .context("Failed to initialize gRPC client from the provided url and credentials")?;
        let semaphore = Arc::new(Semaphore::new(DEFAULT_FETCH_CONCURRENCY));
        let mut set: JoinSet<Result<(u64, Vec<SuiLog>)>> = JoinSet::new();

        for seq_num in start_block..=end_block {
            let remote_checkpoint_url = self.remote_checkpoint_url.clone();
            let client = provider.clone();
            let package_id = self.package_id.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            set.spawn(async move {
                let _permit = permit;

                match Retry::spawn(
                    ExponentialBackoff::from_millis(500)
                        .max_delay(Duration::from_secs(10))
                        .take(3)
                        .map(jitter),
                    move || {
                        let mut client = client.clone();
                        async move {
                            timeout(
                                DEFAULT_REQUEST_TIMEOUT,
                                client.ledger_client().get_checkpoint(
                                    GetCheckpointRequest::by_sequence_number(seq_num)
                                        .with_read_mask(FieldMask {
                                            paths: vec!["transactions".into()],
                                        }),
                                ),
                            )
                            .await
                        }
                    },
                )
                .await
                {
                    Ok(Ok(checkpoint)) => Ok((
                        seq_num,
                        checkpoint_to_sui_logs(
                            &package_id,
                            checkpoint.into_inner().checkpoint().clone(),
                        ),
                    )),
                    _ => {
                        // Fallback to remote checkpoint storage
                        let checkpoint = Retry::spawn(
                            ExponentialBackoff::from_millis(500)
                                .max_delay(Duration::from_secs(10))
                                .map(jitter),
                            || async {
                                let remote_client = reqwest::Client::builder()
                                    .timeout(DEFAULT_REQUEST_TIMEOUT)
                                    .build()
                                    .context(
                                        "Failed to initialize reqwest client for remote call",
                                    )?;
                                let checkpoint_url = format!(
                                    "{}/{}.chk",
                                    remote_checkpoint_url.trim_end_matches('/'),
                                    seq_num
                                );

                                let response = remote_client.get(&checkpoint_url).send().await.context(format!(
                                    "Failed to send checkpoint data request for sequence {} using remote url",
                                    seq_num
                                ))?;
                                if response.status().is_success() {
                                    Ok(response.bytes().await.context(format!(
                                        "Failed to get response bytes for checkpoint data at sequence {} from remote call",
                                        seq_num
                                    ))?)
                                } else {
                                    Err(anyhow!(
                                        "Remote checkpoint call for sequence {} failed with status: {}",
                                        seq_num,
                                        response.status()
                                    ))
                                }
                            },
                        )
                        .await
                        .context(format!(
                            "Failed to get checkpoint data for sequence {} using remote url",
                            seq_num
                        ))?;

                        Ok((
                            seq_num,
                            checkpoint_data_to_sui_logs(
                                &package_id,
                                checkpoint_data_from_bytes(&checkpoint).context(format!(
                                    "Failed to deserialize checkpoint data bytes for sequence {} obtained from remote storage",
                                    seq_num
                                ))?,
                            ),
                        ))
                    }
                }
            });
        }

        let mut block_logs: BTreeMap<u64, Vec<SuiLog>> = BTreeMap::new();
        while let Some(res) = set.join_next().await {
            let result = res
                .context("Failed to join task for fetching checkpoint data")?
                .context("Failed to fetch checkpoint data using gRPC and remote storage")?;
            block_logs.insert(result.0, result.1);
        }

        // Convert SuiLogs to alloy Logs, maintaining order by checkpoint
        let mut logs = Vec::new();
        for (checkpoint_num, sui_logs) in block_logs {
            for (log_index, sui_log) in sui_logs.into_iter().enumerate() {
                if let Some(log) = sui_log_to_alloy_log(sui_log, checkpoint_num, log_index) {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }
}

impl LogsProvider for SuiProvider {
    fn latest_block(&mut self) -> Result<u64> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(self.fetch_latest_checkpoint_async())
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(self.fetch_logs_async(start_block, end_block))
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(self.fetch_checkpoint_timestamp_async(block_number))
    }
}

/// Extracts logs from a gRPC Checkpoint response
fn checkpoint_to_sui_logs(package_id: &str, checkpoint: Checkpoint) -> Vec<SuiLog> {
    let mut logs = Vec::new();

    for tx in checkpoint.transactions {
        let Some(ref events) = tx.events else {
            continue;
        };

        // Get transaction digest
        let tx_digest = tx.digest().to_string();

        for event in &events.events {
            if !event.package_id().eq_ignore_ascii_case(package_id) {
                continue;
            }

            logs.push(SuiLog {
                type_: event.event_type().to_owned(),
                contents: event.contents().value().to_owned(),
                tx_digest: tx_digest.clone(),
            });
        }
    }

    logs
}

/// Deserializes checkpoint data from bytes (used for remote checkpoint storage)
fn checkpoint_data_from_bytes(bytes: &[u8]) -> Result<CheckpointData> {
    let (encoding, data) = bytes.split_first().ok_or(anyhow!("empty bytes"))?;
    if *encoding != 1 {
        return Err(anyhow!("Invalid encoding of checkpoint bytes"));
    }

    Ok(bcs::from_bytes(data)?)
}

/// Extracts logs from a CheckpointData (from remote storage)
fn checkpoint_data_to_sui_logs(
    package_id: &str,
    checkpoint: CheckpointData,
) -> Vec<SuiLog> {
    let mut logs = Vec::new();

    for tx in checkpoint.transactions {
        let Some(ref events) = tx.events else {
            continue;
        };

        // Get transaction digest (it's a TransactionDigest type)
        let tx_digest = tx.transaction.transaction.digest().to_string();

        for event in &events.0 {
            if !event.package_id.to_hex().eq_ignore_ascii_case(package_id) {
                continue;
            }

            logs.push(SuiLog {
                type_: event.type_.to_string(),
                contents: event.contents.clone(),
                tx_digest: tx_digest.clone(),
            });
        }
    }

    logs
}

/// Converts a SuiLog to an alloy Log format
/// 
/// This conversion encodes the Sui event in a way that's compatible with the 
/// framework's handler dispatch mechanism. The event type string and tx_digest are stored 
/// in the data field (length-prefixed) followed by the BCS-encoded contents.
/// 
/// Data format: [event_type_len (4 bytes LE), event_type_bytes, tx_digest_len (4 bytes LE), tx_digest_bytes, bcs_contents]
fn sui_log_to_alloy_log(sui_log: SuiLog, checkpoint_num: u64, log_index: usize) -> Option<Log> {
    // Encode the event type, tx_digest, and contents together
    // Format: [event_type_len (4 bytes LE), event_type_bytes, tx_digest_len (4 bytes LE), tx_digest_bytes, bcs_contents]
    let event_type_bytes = sui_log.type_.as_bytes();
    let event_type_len = (event_type_bytes.len() as u32).to_le_bytes();
    let tx_digest_bytes = sui_log.tx_digest.as_bytes();
    let tx_digest_len = (tx_digest_bytes.len() as u32).to_le_bytes();
    
    let mut data = Vec::with_capacity(
        4 + event_type_bytes.len() + 4 + tx_digest_bytes.len() + sui_log.contents.len()
    );
    data.extend_from_slice(&event_type_len);
    data.extend_from_slice(event_type_bytes);
    data.extend_from_slice(&tx_digest_len);
    data.extend_from_slice(tx_digest_bytes);
    data.extend_from_slice(&sui_log.contents);

    Some(Log {
        block_hash: None,
        block_number: Some(checkpoint_num),
        block_timestamp: None,
        log_index: Some(log_index as u64),
        transaction_hash: None,
        transaction_index: None,
        removed: false,
        inner: alloy::primitives::Log {
            address: Address::ZERO,
            data: alloy::primitives::LogData::new_unchecked(
                vec![],  // No topics needed for Sui - we match on event name
                Bytes::from(data),
            ),
        },
    })
}

/// Parsed Sui log data containing all the extracted fields
pub struct ParsedSuiLog<'a> {
    pub event_name: &'a str,
    pub tx_digest: &'a str,
    pub bcs_contents: &'a [u8],
    pub checkpoint: u64,
}

/// Extracts the event type, tx_digest, and BCS contents from a Sui-encoded alloy Log
/// 
/// Returns ParsedSuiLog containing:
/// - event_name: the last segment of the event type (e.g., "ProviderAdded" from "0x...::market::ProviderAdded")
/// - tx_digest: the transaction digest string
/// - bcs_contents: the BCS-encoded event data
/// - checkpoint: the checkpoint sequence number
pub fn parse_sui_log(log: &Log) -> Option<ParsedSuiLog<'_>> {
    let data = log.data().data.as_ref();
    if data.len() < 4 {
        return None;
    }
    
    // Parse event_type
    let event_type_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + event_type_len + 4 {
        return None;
    }
    
    let event_type = std::str::from_utf8(&data[4..4 + event_type_len]).ok()?;
    let event_name = event_type.split("::").last()?;
    
    // Parse tx_digest
    let tx_digest_offset = 4 + event_type_len;
    let tx_digest_len = u32::from_le_bytes([
        data[tx_digest_offset],
        data[tx_digest_offset + 1],
        data[tx_digest_offset + 2],
        data[tx_digest_offset + 3],
    ]) as usize;
    
    if data.len() < tx_digest_offset + 4 + tx_digest_len {
        return None;
    }
    
    let tx_digest = std::str::from_utf8(
        &data[tx_digest_offset + 4..tx_digest_offset + 4 + tx_digest_len]
    ).ok()?;
    
    // BCS contents start after tx_digest
    let bcs_contents = &data[tx_digest_offset + 4 + tx_digest_len..];
    
    // Get checkpoint from block_number
    let checkpoint = log.block_number.unwrap_or(0);
    
    Some(ParsedSuiLog {
        event_name,
        tx_digest,
        bcs_contents,
        checkpoint,
    })
}

