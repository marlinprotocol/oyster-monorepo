use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sui_rpc_api::client::AuthInterceptor;
use sui_rpc_api::Client;
use sui_storage::blob::Blob;
use sui_types::base_types::SuiAddress;
use sui_types::full_checkpoint_content::CheckpointData;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use indexer_framework::chain::{ChainHandler, FromLog};
use indexer_framework::events::{self, JobEvent};
use indexer_framework::schema::JobEventRecord;
use indexer_framework::SaturatingConvert;

const DEFAULT_FETCH_CONCURRENCY: usize = 200;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Sui market program logs
#[derive(Debug, Deserialize)]
struct JobOpened {
    job_id: u128,
    owner: SuiAddress,
    provider: SuiAddress,
    metadata: String,
    rate: u64,
    balance: u64,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct JobClosed {
    job_id: u128,
}

#[derive(Debug, Deserialize)]
struct JobDeposited {
    job_id: u128,
    from: SuiAddress,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct JobSettled {
    job_id: u128,
    amount: u64,
    settled_until_ms: u64,
}

#[derive(Debug, Deserialize)]
struct JobMetadataUpdated {
    job_id: u128,
    new_metadata: String,
}

#[derive(Debug, Deserialize)]
struct JobWithdrew {
    job_id: u128,
    to: SuiAddress,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateInitiated {
    job_id: u128,
    new_rate: u64,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateCancelled {
    job_id: u128,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateFinalized {
    job_id: u128,
    new_rate: u64,
}

#[derive(Debug, Clone)]
pub struct SuiLog {
    pub transaction_digest: String,
    pub checkpoint_timestamp_ms: i64,
    pub sender: String,
    pub type_: String,
    pub contents: Vec<u8>,
}

impl FromLog for SuiLog {
    fn from_log(&self) -> Result<Option<JobEvent>> {
        let Some(event_name) = self.type_.split("::").last() else {
            // Invalid event type, skip
            return Ok(None);
        };

        return match event_name {
            "JobOpened" => {
                let decoded_data: JobOpened = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::Opened(events::JobOpened {
                    job_id: decoded_data.job_id.to_string(),
                    owner: decoded_data.owner.to_string(),
                    provider: decoded_data.provider.to_string(),
                    metadata: decoded_data.metadata,
                    rate: U256::from(decoded_data.rate),
                    balance: U256::from(decoded_data.balance),
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            "JobClosed" => {
                let decoded_data: JobClosed = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::Closed(events::JobClosed {
                    job_id: decoded_data.job_id.to_string(),
                })))
            }
            "JobDeposited" => {
                let decoded_data: JobDeposited = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::Deposited(events::JobDeposited {
                    job_id: decoded_data.job_id.to_string(),
                    from: decoded_data.from.to_string(),
                    amount: U256::from(decoded_data.amount),
                })))
            }
            "JobSettled" => {
                let decoded_data: JobSettled = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::Settled(events::JobSettled {
                    job_id: decoded_data.job_id.to_string(),
                    amount: U256::from(decoded_data.amount),
                    timestamp: decoded_data.settled_until_ms.saturating_to(),
                })))
            }
            "JobMetadataUpdated" => {
                let decoded_data: JobMetadataUpdated = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::MetadataUpdated(
                    events::JobMetadataUpdated {
                        job_id: decoded_data.job_id.to_string(),
                        new_metadata: decoded_data.new_metadata,
                    },
                )))
            }
            "JobWithdrew" => {
                let decoded_data: JobWithdrew = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::Withdrew(events::JobWithdrew {
                    job_id: decoded_data.job_id.to_string(),
                    to: decoded_data.to.to_string(),
                    amount: U256::from(decoded_data.amount),
                })))
            }
            "JobReviseRateInitiated" => {
                let decoded_data: JobReviseRateInitiated = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::ReviseRateInitiated(
                    events::JobReviseRateInitiated {
                        job_id: decoded_data.job_id.to_string(),
                        new_rate: U256::from(decoded_data.new_rate),
                    },
                )))
            }
            "JobReviseRateCancelled" => {
                let decoded_data: JobReviseRateCancelled = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::ReviseRateCancelled(
                    events::JobReviseRateCancelled {
                        job_id: decoded_data.job_id.to_string(),
                    },
                )))
            }
            "JobReviseRateFinalized" => {
                let decoded_data: JobReviseRateFinalized = bcs::from_bytes(&self.contents)?;

                Ok(Some(JobEvent::ReviseRateFinalized(
                    events::JobReviseRateFinalized {
                        job_id: decoded_data.job_id.to_string(),
                        new_rate: U256::from(decoded_data.new_rate),
                    },
                )))
            }
            _ => return Ok(None),
        };
    }
}

#[derive(Clone)]
pub struct SuiProvider {
    pub remote_checkpoint_url: String,
    pub grpc_url: String,
    pub rpc_username: Option<String>,
    pub rpc_password: Option<String>,
    pub package_id: String,
    pub provider: String,
}

impl SuiProvider {
    fn get_client(&self) -> Result<Client> {
        if let Some(username) = &self.rpc_username {
            Ok(Client::new(&self.grpc_url)?
                .with_auth(AuthInterceptor::basic(username, self.rpc_password.clone())))
        } else {
            Ok(Client::new(&self.grpc_url)?)
        }
    }

    fn checkpoint_data_to_sui_logs(&self, checkpoint: CheckpointData) -> Vec<SuiLog> {
        let mut logs = Vec::new();

        for tx in checkpoint.transactions {
            let Some(events) = tx.events else {
                continue;
            };

            for event in events.data {
                if event.package_id.to_string() != self.package_id {
                    continue;
                }

                logs.push(SuiLog {
                    transaction_digest: tx.transaction.digest().base58_encode(),
                    checkpoint_timestamp_ms: checkpoint
                        .checkpoint_summary
                        .timestamp_ms
                        .saturating_to(),
                    sender: event.sender.to_string(),
                    type_: event.type_.to_string(),
                    contents: event.contents,
                });
            }
        }

        logs
    }
}

impl ChainHandler for SuiProvider {
    type RawLog = SuiLog;

    async fn fetch_latest_block(&self) -> Result<u64> {
        let provider = self.get_client()?;
        let current_checkpoint = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            || async { timeout(DEFAULT_REQUEST_TIMEOUT, provider.get_latest_checkpoint()).await },
        )
        .await??;

        Ok(current_checkpoint.sequence_number)
    }

    async fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<BTreeMap<u64, Vec<Self::RawLog>>> {
        let provider = Arc::new(self.get_client()?);
        let semaphore = Arc::new(Semaphore::new(DEFAULT_FETCH_CONCURRENCY));
        let mut set: JoinSet<Result<(u64, CheckpointData)>> = JoinSet::new();

        for seq_num in start_block..=end_block {
            let remote_checkpoint_url = self.remote_checkpoint_url.clone();
            let client = provider.clone();
            let permit = semaphore.clone().acquire_owned().await?;

            set.spawn(async move {
                let _permit = permit;

                match Retry::spawn(
                    ExponentialBackoff::from_millis(500)
                        .max_delay(Duration::from_secs(10))
                        .take(3)
                        .map(jitter),
                    || async {
                        timeout(DEFAULT_REQUEST_TIMEOUT, client.get_full_checkpoint(seq_num)).await
                    },
                )
                .await
                {
                    Ok(checkpoint) => Ok((seq_num, checkpoint?)),
                    Err(_) => {
                        let checkpoint = Retry::spawn(
                            ExponentialBackoff::from_millis(500)
                                .max_delay(Duration::from_secs(10))
                                .map(jitter),
                            || async {
                                let remote_client = reqwest::Client::builder()
                                    .timeout(DEFAULT_REQUEST_TIMEOUT)
                                    .build()?;
                                let checkpoint_url =
                                    format!("{}/{}.chk", remote_checkpoint_url, seq_num);

                                let response = remote_client.get(&checkpoint_url).send().await?;
                                if response.status().is_success() {
                                    Ok(response.bytes().await?)
                                } else {
                                    Err(anyhow!(
                                        "Checkpoint call failed with status: {}",
                                        response.status()
                                    ))
                                }
                            },
                        )
                        .await?;

                        Ok((seq_num, Blob::from_bytes(&checkpoint)?))
                    }
                }
            });
        }

        let mut block_logs: BTreeMap<u64, Vec<SuiLog>> = BTreeMap::new();
        while let Some(res) = set.join_next().await {
            let result = res??;
            block_logs.insert(result.0, self.checkpoint_data_to_sui_logs(result.1));
        }

        Ok(block_logs)
    }

    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &Vec<SuiLog>,
        active_jobs: &mut HashSet<String>,
    ) -> Result<Vec<JobEventRecord>> {
        let mut job_event_records = vec![];

        for (seq, log) in logs.iter().enumerate() {
            let Some(job_event) = log.from_log()? else {
                continue;
            };

            // Match event signature and decode
            let (job_id, event_name, event_data) = match job_event {
                JobEvent::Opened(event) => {
                    // Check if provider matches the target
                    if event.provider != self.provider {
                        continue;
                    }

                    active_jobs.insert(event.job_id.clone());
                    (
                        event.job_id.clone(),
                        "JobOpened",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::Closed(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    active_jobs.remove(&event.job_id);

                    (
                        event.job_id.clone(),
                        "JobClosed",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::Settled(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobSettled",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::Deposited(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobDeposited",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::Withdrew(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobWithdrew",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::ReviseRateInitiated(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobReviseRateInitiated",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::ReviseRateCancelled(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobReviseRateCancelled",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::ReviseRateFinalized(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobReviseRateFinalized",
                        serde_json::to_value(event)?,
                    )
                }
                JobEvent::MetadataUpdated(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    (
                        event.job_id.clone(),
                        "JobMetadataUpdated",
                        serde_json::to_value(event)?,
                    )
                }
            };

            // Build JobEventRecord
            let record = JobEventRecord {
                block_id: block_number.saturating_to(),
                tx_hash: log.transaction_digest.clone(),
                event_seq: seq.saturating_to(),
                block_timestamp: DateTime::from_timestamp_millis(log.checkpoint_timestamp_ms)
                    .unwrap_or(Utc::now()),
                sender: log.sender.clone(),
                event_name: event_name.to_string(),
                event_data,
                job_id: job_id,
            };

            job_event_records.push(record);
        }

        Ok(job_event_records)
    }
}
