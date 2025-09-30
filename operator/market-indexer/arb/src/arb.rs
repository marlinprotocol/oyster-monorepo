use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::hex::ToHexExt;
use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::eth::Log;
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use indexer_framework::chain::{ChainHandler, FromLog};
use indexer_framework::schema::JobEventRecord;
use indexer_framework::{events::*, SaturatingConvert};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MarketV1Contract,
    "./abi/MarketV1min.json"
);

const DEFAULT_FETCH_CONCURRENCY: usize = 200;

#[derive(Debug, Clone)]
pub struct ArbLog(pub Log);

impl FromLog for ArbLog {
    fn from_log(&self) -> Result<Option<JobEvent>> {
        return match &self.0.topic0() {
            Some(&MarketV1Contract::JobOpened::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobOpened::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::Opened(JobOpened {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    owner: decoded_data.owner.encode_hex_with_prefix(),
                    provider: decoded_data.provider.encode_hex_with_prefix(),
                    metadata: decoded_data.metadata,
                    rate: decoded_data.rate,
                    balance: decoded_data.balance,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&MarketV1Contract::JobClosed::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobClosed::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::Closed(JobClosed {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                })))
            }
            Some(&MarketV1Contract::JobSettled::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobSettled::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::Settled(JobSettled {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&MarketV1Contract::JobDeposited::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobDeposited::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::Deposited(JobDeposited {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    from: decoded_data.from.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&MarketV1Contract::JobWithdrew::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobWithdrew::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::Withdrew(JobWithdrew {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    to: decoded_data.to.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&MarketV1Contract::JobReviseRateInitiated::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateInitiated::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::ReviseRateInitiated(
                    JobReviseRateInitiated {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&MarketV1Contract::JobReviseRateCancelled::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateCancelled::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::ReviseRateCancelled(
                    JobReviseRateCancelled {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                    },
                )))
            }
            Some(&MarketV1Contract::JobReviseRateFinalized::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateFinalized::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::ReviseRateFinalized(
                    JobReviseRateFinalized {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&MarketV1Contract::JobMetadataUpdated::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobMetadataUpdated::decode_log(&self.0.inner)?.data;

                Ok(Some(JobEvent::MetadataUpdated(JobMetadataUpdated {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    new_metadata: decoded_data.metadata,
                })))
            }
            _ => Ok(None), // unknown event, skip
        };
    }
}

#[derive(Clone)]
pub struct ArbProvider {
    pub rpc_url: Url,
    pub contract: Address,
    pub provider: Address,
}

impl ChainHandler for ArbProvider {
    type RawLog = ArbLog;

    async fn fetch_latest_block(&self) -> Result<u64> {
        let provider = RootProvider::<Ethereum>::new_http(self.rpc_url.clone());
        let block_number = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            || async { provider.get_block_number().await },
        )
        .await?;
        Ok(block_number)
    }

    async fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<BTreeMap<u64, Vec<ArbLog>>> {
        let provider = Arc::new(RootProvider::<Ethereum>::new_http(self.rpc_url.clone()));
        let logs = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            || async {
                provider
                    .get_logs(
                        &Filter::new()
                            .events(vec![
                                MarketV1Contract::JobOpened::SIGNATURE,
                                MarketV1Contract::JobSettled::SIGNATURE,
                                MarketV1Contract::JobClosed::SIGNATURE,
                                MarketV1Contract::JobDeposited::SIGNATURE,
                                MarketV1Contract::JobWithdrew::SIGNATURE,
                                MarketV1Contract::JobReviseRateInitiated::SIGNATURE,
                                MarketV1Contract::JobReviseRateCancelled::SIGNATURE,
                                MarketV1Contract::JobReviseRateFinalized::SIGNATURE,
                                MarketV1Contract::JobMetadataUpdated::SIGNATURE,
                            ])
                            .from_block(start_block)
                            .to_block(end_block)
                            .address(self.contract),
                    )
                    .await
            },
        )
        .await?;

        let block_nums: HashSet<u64> = logs.iter().filter_map(|log| log.block_number).collect();
        let mut block_timestamp_map = HashMap::new();
        let semaphore = Arc::new(Semaphore::new(DEFAULT_FETCH_CONCURRENCY));
        let mut set: JoinSet<Result<(u64, u64)>> = JoinSet::new();

        for block in block_nums {
            let client = provider.clone();
            let Ok(permit) = semaphore.clone().acquire_owned().await else {
                continue;
            };

            set.spawn(async move {
                let _permit = permit;

                let block_data = Retry::spawn(
                    ExponentialBackoff::from_millis(500)
                        .max_delay(Duration::from_secs(10))
                        .map(jitter),
                    || async { client.get_block_by_number(block.into()).await },
                )
                .await?
                .ok_or(anyhow!("Block data is empty!"))?;

                return Ok((block, block_data.header.timestamp));
            });
        }

        while let Some(res) = set.join_next().await {
            let Ok(Ok(result)) = res else {
                continue;
            };

            block_timestamp_map.insert(result.0, result.1);
        }

        let mut block_logs: BTreeMap<u64, Vec<ArbLog>> = BTreeMap::new();
        for mut log in logs {
            if let Some(block_number) = log.block_number {
                log.block_timestamp = block_timestamp_map.get(&block_number).cloned();
                block_logs
                    .entry(block_number)
                    .or_insert_with(Vec::new)
                    .push(ArbLog(log));
            }
        }

        Ok(block_logs)
    }

    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &Vec<ArbLog>,
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
                    if event.provider != self.provider.encode_hex_with_prefix() {
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

            let block_timestamp: DateTime<Utc> = log
                .0
                .block_timestamp
                .map(|ts| DateTime::from_timestamp_secs(ts.saturating_to()))
                .flatten()
                .unwrap_or_else(|| Utc::now());

            // Build JobEventRecord
            let record = JobEventRecord {
                block_id: block_number.saturating_to(),
                tx_hash: log
                    .0
                    .transaction_hash
                    .unwrap_or_default()
                    .encode_hex_with_prefix(),
                event_seq: seq.saturating_to(),
                block_timestamp: block_timestamp,
                sender: log.0.address().encode_hex_with_prefix(),
                event_name: event_name.to_string(),
                event_data,
                job_id: job_id,
            };

            job_event_records.push(record);
        }

        Ok(job_event_records)
    }
}
