use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::eth::Log;
use anyhow::{anyhow, Context, Result};
use indexer_framework::LogsProvider;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sui_rpc::client::{Client, HeadersInterceptor, ResponseExt};
use sui_rpc::field::FieldMask;
use sui_rpc::proto::sui::rpc::v2::{Checkpoint, GetCheckpointRequest};
use sui_sdk_types::CheckpointData;
use tokio::time::timeout;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tracing::info;

use crate::constants::{
    CHECKPOINT_BCS_ENCODING, DEFAULT_FETCH_CONCURRENCY, DEFAULT_REQUEST_TIMEOUT, GRPC_AUTH_TOKEN,
};
use futures::stream::{self, StreamExt};

pub struct SuiProvider {
    pub remote_checkpoint_url: String,
    pub package_id: String,
    /// Shared tokio runtime for async operations
    /// Creating a runtime is expensive, so we reuse one instance
    runtime: tokio::runtime::Runtime,
    /// Shared gRPC client for connection reuse across all operations
    /// Cloning this shares the underlying connection pool
    grpc_client: Client,
    /// Shared HTTP client for remote checkpoint fallback
    /// Enables connection pooling and TLS session reuse
    http_client: reqwest::Client,
}

impl SuiProvider {
    pub fn new(
        remote_checkpoint_url: String,
        grpc_url: String,
        rpc_username: Option<String>,
        rpc_password: Option<String>,
        rpc_token: Option<String>,
        package_id: String,
    ) -> Result<Self> {
        // Create a multi-threaded runtime for better parallelism
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        // Create clients inside the runtime context
        // Client::new() requires a Tokio runtime to be available
        let (grpc_client, http_client) = runtime.block_on(async {
            // Create the shared gRPC client with appropriate authentication
            // This connection will be reused across all operations
            let grpc_client = if let Some(ref username) = rpc_username {
                let mut headers = HeadersInterceptor::default();

                headers.basic_auth(username, rpc_password.clone());

                Client::new(&grpc_url)
                    .context("Failed to create gRPC client")?
                    .with_headers(headers)
            } else if let Some(ref token) = rpc_token {
                let mut headers = HeadersInterceptor::default();

                headers.headers_mut().insert(
                    GRPC_AUTH_TOKEN,
                    token.parse().context("Invalid auth token")?,
                );

                Client::new(&grpc_url)
                    .context("Failed to create gRPC client")?
                    .with_headers(headers)
            } else {
                Client::new(&grpc_url).context("Failed to create gRPC client")?
            };

            // Create the shared HTTP client for remote checkpoint fallback
            // This enables connection pooling and TLS session reuse
            let http_client = reqwest::Client::builder()
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .pool_max_idle_per_host(DEFAULT_FETCH_CONCURRENCY)
                .pool_idle_timeout(Duration::from_secs(90)) // Keep connections alive longer
                .tcp_keepalive(Duration::from_secs(60))
                .build()
                .context("Failed to create HTTP client")?;

            Ok::<_, anyhow::Error>((grpc_client, http_client))
        })?;

        Ok(Self {
            remote_checkpoint_url,
            package_id,
            runtime,
            grpc_client,
            http_client,
        })
    }
}

/// Intermediate representation of a Sui log/event
#[derive(Debug, Clone)]
pub struct SuiLog {
    pub type_: String,
    pub contents: Vec<u8>,
    pub tx_digest: String,
}

impl SuiProvider {
    /// Returns a clone of the shared gRPC client
    /// Cloning shares the underlying connection pool
    fn get_client(&self) -> Client {
        self.grpc_client.clone()
    }

    /// Fetches the latest checkpoint sequence number
    async fn fetch_latest_checkpoint_async(&self) -> Result<u64> {
        // Clone the shared client - this reuses the underlying connection
        let provider = self.get_client();

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
        // Clone the shared client - this reuses the underlying connection
        let provider = self.get_client();

        let checkpoint = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                async move {
                    timeout(
                        DEFAULT_REQUEST_TIMEOUT,
                        provider.ledger_client().get_checkpoint(
                            GetCheckpointRequest::by_sequence_number(checkpoint_number),
                        ),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching checkpoint timestamp")?
        .context("Request failed for fetching checkpoint timestamp")?;

        // Get timestamp from response - Sui timestamps are in milliseconds, convert to seconds
        let timestamp_ms = checkpoint
            .timestamp_ms()
            .ok_or_else(|| anyhow!("Checkpoint {} has no timestamp", checkpoint_number))?;

        if timestamp_ms == 0 {
            return Err(anyhow!(
                "Checkpoint {} has invalid timestamp (0)",
                checkpoint_number
            ));
        }

        Ok(timestamp_ms / 1000)
    }
}

/// Fetches a single checkpoint, trying gRPC first then falling back to HTTP
async fn fetch_single_checkpoint(
    seq_num: u64,
    grpc_client: Client,
    http_client: Arc<reqwest::Client>,
    remote_checkpoint_url: &str,
    package_id: &str,
) -> Result<(u64, Vec<SuiLog>)> {
    // Try gRPC first
    let grpc_result = Retry::spawn(
        ExponentialBackoff::from_millis(100)
            .max_delay(Duration::from_secs(2))
            .take(2)
            .map(jitter),
        || {
            let mut client = grpc_client.clone();
            async move {
                timeout(
                    DEFAULT_REQUEST_TIMEOUT,
                    client.ledger_client().get_checkpoint(
                        GetCheckpointRequest::by_sequence_number(seq_num).with_read_mask(
                            FieldMask {
                                paths: vec!["transactions".into()],
                            },
                        ),
                    ),
                )
                .await
            }
        },
    )
    .await;

    match grpc_result {
        Ok(Ok(checkpoint)) => {
            return Ok((
                seq_num,
                checkpoint_to_sui_logs(package_id, checkpoint.into_inner().checkpoint().clone()),
            ));
        }
        _ => {
            // Fallback to remote checkpoint storage via HTTP
        }
    }

    // HTTP fallback
    let checkpoint_bytes = Retry::spawn(
        ExponentialBackoff::from_millis(100)
            .max_delay(Duration::from_secs(2))
            .take(3)
            .map(jitter),
        || {
            let http = http_client.clone();
            let url = format!(
                "{}/{}.chk",
                remote_checkpoint_url.trim_end_matches('/'),
                seq_num
            );
            async move {
                let response = http
                    .get(&url)
                    .send()
                    .await
                    .context(format!("HTTP request failed for checkpoint {}", seq_num))?;
                if response.status().is_success() {
                    Ok(response.bytes().await.context(format!(
                        "Failed to read response body for checkpoint {}",
                        seq_num
                    ))?)
                } else {
                    Err(anyhow!(
                        "HTTP {} for checkpoint {}",
                        response.status(),
                        seq_num
                    ))
                }
            }
        },
    )
    .await
    .context(format!("All retries failed for checkpoint {}", seq_num))?;

    Ok((
        seq_num,
        checkpoint_data_to_sui_logs(
            package_id,
            checkpoint_data_from_bytes(&checkpoint_bytes)
                .context(format!("Failed to deserialize checkpoint {}", seq_num))?,
        ),
    ))
}

impl SuiProvider {
    /// Fetches logs/events for a range of checkpoints
    ///
    /// This fetches checkpoints in parallel (limited by semaphore) for performance,
    /// but returns them sorted by checkpoint number so the caller can process
    /// them sequentially in chronological order.
    async fn fetch_logs_async(&self, start_block: u64, end_block: u64) -> Result<Vec<Log>> {
        use std::sync::atomic::{AtomicU64, Ordering};

        let fetch_start = Instant::now();
        let checkpoint_count = end_block - start_block + 1;

        // Use the shared clients - cloning shares the underlying connection pool
        let grpc_client = self.get_client();
        let http_client = Arc::new(self.http_client.clone());

        // Progress tracking
        let completed = Arc::new(AtomicU64::new(0));

        info!(
            checkpoint_count,
            concurrency = DEFAULT_FETCH_CONCURRENCY,
            "starting checkpoint fetch"
        );

        // Use buffer_unordered instead of JoinSet to avoid spawning all tasks upfront
        // This processes checkpoints as a stream with bounded concurrency
        let remote_checkpoint_url = self.remote_checkpoint_url.clone();
        let package_id = self.package_id.clone();

        let results: Vec<Result<(u64, Vec<SuiLog>)>> = stream::iter(start_block..=end_block)
            .map(|seq_num| {
                let client = grpc_client.clone();
                let http = http_client.clone();
                let url_base = remote_checkpoint_url.clone();
                let pkg_id = package_id.clone();
                let completed = completed.clone();
                let checkpoint_count = checkpoint_count;
                let fetch_start = fetch_start;

                async move {
                    let result =
                        fetch_single_checkpoint(seq_num, client, http, &url_base, &pkg_id).await;

                    // Track progress
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if done % 500 == 0 || done == checkpoint_count {
                        let elapsed = fetch_start.elapsed();
                        let rate = if elapsed.as_secs_f64() > 0.0 {
                            done as f64 / elapsed.as_secs_f64()
                        } else {
                            0.0
                        };
                        info!(
                            completed = done,
                            total = checkpoint_count,
                            elapsed_secs = elapsed.as_secs(),
                            rate = format!("{:.1}/s", rate),
                            "fetch progress"
                        );
                    }

                    result
                }
            })
            .buffer_unordered(DEFAULT_FETCH_CONCURRENCY)
            .collect()
            .await;

        let fetch_elapsed = fetch_start.elapsed();
        let rate = if fetch_elapsed.as_secs_f64() > 0.0 {
            checkpoint_count as f64 / fetch_elapsed.as_secs_f64()
        } else {
            0.0
        };
        info!(
            checkpoint_count,
            completed = completed.load(Ordering::Relaxed),
            fetch_time_secs = fetch_elapsed.as_secs(),
            rate = format!("{:.1}/s", rate),
            "checkpoint fetch complete"
        );

        // Collect results into sorted map
        let collect_start = Instant::now();
        let mut block_logs: BTreeMap<u64, Vec<SuiLog>> = BTreeMap::new();
        for result in results {
            let (seq_num, logs) = result.context("Failed to fetch checkpoint data")?;
            block_logs.insert(seq_num, logs);
        }
        let collect_elapsed = collect_start.elapsed();

        // Convert SuiLogs to alloy Logs, maintaining order by checkpoint (BTreeMap is sorted)
        let convert_start = Instant::now();
        let mut logs = Vec::new();
        let mut total_events = 0usize;
        for (checkpoint_num, sui_logs) in block_logs {
            total_events += sui_logs.len();
            for (log_index, sui_log) in sui_logs.into_iter().enumerate() {
                if let Some(log) = sui_log_to_alloy_log(sui_log, checkpoint_num, log_index) {
                    logs.push(log);
                }
            }
        }
        let convert_elapsed = convert_start.elapsed();

        let total_elapsed = fetch_start.elapsed();
        info!(
            checkpoint_count,
            total_events,
            logs_count = logs.len(),
            collect_time_ms = collect_elapsed.as_millis(),
            convert_time_ms = convert_elapsed.as_millis(),
            total_time_ms = total_elapsed.as_millis(),
            checkpoints_per_sec = (checkpoint_count as f64 / total_elapsed.as_secs_f64()) as u64,
            "checkpoint processing complete"
        );

        Ok(logs)
    }
}

impl LogsProvider for SuiProvider {
    fn latest_block(&mut self) -> Result<u64> {
        // Reuse the shared runtime instead of creating a new one each time
        self.runtime.block_on(self.fetch_latest_checkpoint_async())
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        // Reuse the shared runtime instead of creating a new one each time
        self.runtime
            .block_on(self.fetch_logs_async(start_block, end_block))
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        // Reuse the shared runtime instead of creating a new one each time
        self.runtime
            .block_on(self.fetch_checkpoint_timestamp_async(block_number))
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
    if *encoding != CHECKPOINT_BCS_ENCODING {
        return Err(anyhow!(
            "Invalid encoding of checkpoint bytes: expected {}, got {}",
            CHECKPOINT_BCS_ENCODING,
            encoding
        ));
    }

    Ok(bcs::from_bytes(data)?)
}

/// Extracts logs from a CheckpointData (from remote storage)
fn checkpoint_data_to_sui_logs(package_id: &str, checkpoint: CheckpointData) -> Vec<SuiLog> {
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
        4 + event_type_bytes.len() + 4 + tx_digest_bytes.len() + sui_log.contents.len(),
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
                vec![], // No topics needed for Sui - we match on event name
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
    use tracing::debug;

    let checkpoint = log.block_number.unwrap_or(0);
    let data = log.data().data.as_ref();

    if data.len() < 4 {
        debug!(
            checkpoint,
            data_len = data.len(),
            "parse_sui_log: data too short for event_type length header"
        );
        return None;
    }

    // Parse event_type
    let event_type_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + event_type_len + 4 {
        debug!(
            checkpoint,
            data_len = data.len(),
            event_type_len,
            required = 4 + event_type_len + 4,
            "parse_sui_log: data too short for event_type + tx_digest header"
        );
        return None;
    }

    let event_type = match std::str::from_utf8(&data[4..4 + event_type_len]) {
        Ok(s) => s,
        Err(e) => {
            debug!(
                checkpoint,
                event_type_len,
                error = %e,
                "parse_sui_log: event_type is not valid UTF-8"
            );
            return None;
        }
    };

    let event_name = match event_type.split("::").last() {
        Some(name) => name,
        None => {
            debug!(
                checkpoint,
                event_type, "parse_sui_log: event_type has no '::' separator"
            );
            return None;
        }
    };

    // Parse tx_digest
    let tx_digest_offset = 4 + event_type_len;
    let tx_digest_len = u32::from_le_bytes([
        data[tx_digest_offset],
        data[tx_digest_offset + 1],
        data[tx_digest_offset + 2],
        data[tx_digest_offset + 3],
    ]) as usize;

    if data.len() < tx_digest_offset + 4 + tx_digest_len {
        debug!(
            checkpoint,
            data_len = data.len(),
            tx_digest_offset,
            tx_digest_len,
            required = tx_digest_offset + 4 + tx_digest_len,
            "parse_sui_log: data too short for tx_digest"
        );
        return None;
    }

    let tx_digest = match std::str::from_utf8(
        &data[tx_digest_offset + 4..tx_digest_offset + 4 + tx_digest_len],
    ) {
        Ok(s) => s,
        Err(e) => {
            debug!(
                checkpoint,
                tx_digest_len,
                error = %e,
                "parse_sui_log: tx_digest is not valid UTF-8"
            );
            return None;
        }
    };

    // BCS contents start after tx_digest
    let bcs_contents = &data[tx_digest_offset + 4 + tx_digest_len..];

    Some(ParsedSuiLog {
        event_name,
        tx_digest,
        bcs_contents,
        checkpoint,
    })
}
