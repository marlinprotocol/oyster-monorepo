use std::collections::{BTreeMap, HashSet};
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
use anyhow::Result;
use serde::Serialize;
use sqlx::types::chrono::{DateTime, Utc};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::schema::JobEventRecord;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Serialize)]
    MarketV1Contract,
    "./abi/MarketV1min.json"
);

pub trait ArbHandler {
    async fn latest_block_with_retries(&mut self) -> Result<u64>;
    async fn logs_with_retries(&self, start_block: u64, end_block: u64) -> Result<Vec<Log>>;
    fn group_logs_by_block(&self, logs: Vec<Log>) -> BTreeMap<u64, Vec<Log>>;
    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &Vec<Log>,
        active_jobs: &mut HashSet<String>,
    ) -> Result<Vec<JobEventRecord>>;
}

#[derive(Clone)]
pub struct RpcProvider {
    pub url: Url,
    pub contract: Address,
    pub provider: Address,
}

impl ArbHandler for RpcProvider {
    async fn latest_block_with_retries(&mut self) -> Result<u64> {
        let provider = RootProvider::<Ethereum>::new_http(self.url.clone());
        let block_number = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter),
            || async { provider.get_block_number().await },
        )
        .await?;
        Ok(block_number)
    }

    async fn logs_with_retries(&self, start_block: u64, end_block: u64) -> Result<Vec<Log>> {
        let provider = RootProvider::<Ethereum>::new_http(self.url.clone());
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
        Ok(logs)
    }

    fn group_logs_by_block(&self, logs: Vec<Log>) -> BTreeMap<u64, Vec<Log>> {
        let mut block_logs: BTreeMap<u64, Vec<Log>> = BTreeMap::new();

        for log in logs {
            if let Some(block_number) = log.block_number {
                block_logs
                    .entry(block_number)
                    .or_insert_with(Vec::new)
                    .push(log);
            }
        }

        block_logs
    }

    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &Vec<Log>,
        active_jobs: &mut HashSet<String>,
    ) -> Result<Vec<JobEventRecord>> {
        let mut job_event_records = vec![];

        for (seq, log) in logs.iter().enumerate() {
            // Match event signature and decode
            let (job_id, event_name, event_data) = match log.topic0() {
                Some(&MarketV1Contract::JobOpened::SIGNATURE_HASH) => {
                    let decoded = MarketV1Contract::JobOpened::decode_log(&log.inner)?;
                    // Check if provider matches the target
                    if decoded.provider != self.provider {
                        continue;
                    }
                    let job_id = decoded.job.encode_hex_with_prefix();
                    active_jobs.insert(job_id.clone());
                    (job_id, "JobOpened", serde_json::to_value(decoded.data)?)
                }
                Some(&MarketV1Contract::JobClosed::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobClosed::decode_log(&log.inner)?;
                    active_jobs.remove(&job_id);
                    (job_id, "JobClosed", serde_json::to_value(decoded.data)?)
                }
                Some(&MarketV1Contract::JobSettled::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobSettled::decode_log(&log.inner)?;
                    (job_id, "JobSettled", serde_json::to_value(decoded.data)?)
                }
                Some(&MarketV1Contract::JobDeposited::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobDeposited::decode_log(&log.inner)?;
                    (job_id, "JobDeposited", serde_json::to_value(decoded.data)?)
                }
                Some(&MarketV1Contract::JobWithdrew::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobWithdrew::decode_log(&log.inner)?;
                    (job_id, "JobWithdrew", serde_json::to_value(decoded.data)?)
                }
                Some(&MarketV1Contract::JobReviseRateInitiated::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobReviseRateInitiated::decode_log(&log.inner)?;
                    (
                        job_id,
                        "JobReviseRateInitiated",
                        serde_json::to_value(decoded.data)?,
                    )
                }
                Some(&MarketV1Contract::JobReviseRateCancelled::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobReviseRateCancelled::decode_log(&log.inner)?;
                    (
                        job_id,
                        "JobReviseRateCancelled",
                        serde_json::to_value(decoded.data)?,
                    )
                }
                Some(&MarketV1Contract::JobReviseRateFinalized::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobReviseRateFinalized::decode_log(&log.inner)?;
                    (
                        job_id,
                        "JobReviseRateFinalized",
                        serde_json::to_value(decoded.data)?,
                    )
                }
                Some(&MarketV1Contract::JobMetadataUpdated::SIGNATURE_HASH) => {
                    let job_id = log.topics()[1].encode_hex_with_prefix();
                    if !active_jobs.contains(&job_id) {
                        continue;
                    }
                    let decoded = MarketV1Contract::JobMetadataUpdated::decode_log(&log.inner)?;
                    (
                        job_id,
                        "JobMetadataUpdated",
                        serde_json::to_value(decoded.data)?,
                    )
                }
                _ => continue, // unknown event, skip
            };

            let block_timestamp: DateTime<Utc> = log
                .block_timestamp
                .map(|ts| DateTime::from_timestamp_secs(ts as i64))
                .flatten()
                .unwrap_or_else(|| Utc::now());

            // Build JobEventRecord
            let record = JobEventRecord {
                block_id: block_number as i64,
                tx_hash: log
                    .transaction_hash
                    .unwrap_or_default()
                    .encode_hex_with_prefix(),
                event_seq: seq as i64,
                block_timestamp: block_timestamp,
                sender: log.address().encode_hex_with_prefix(),
                event_name: event_name.to_string(),
                event_data,
                job_id: job_id,
            };

            job_event_records.push(record);
        }

        Ok(job_event_records)
    }
}
