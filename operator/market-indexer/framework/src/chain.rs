use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use anyhow::{Context, Result};

use crate::events::JobEvent;
use crate::schema::{JobEventName, JobEventRecord};

// Define trait for conversion from raw log to structured JobEvent
pub trait FromLog: Sized {
    fn to_job_event(&self) -> Result<Option<JobEvent>>;
}

/// Trait every chain must implement
pub trait ChainHandler {
    type RawLog: FromLog;

    /// Fetch chain ID from the RPC
    fn fetch_chain_id(&self) -> impl Future<Output = Result<String>> + Send;

    /// Fetch EXTRA_DECIMALS value from the Market contract
    fn fetch_extra_decimals(&self) -> impl Future<Output = Result<i64>> + Send;

    /// Fetch latest block/checkpoint/slot for the chain
    fn fetch_latest_block(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Fetch raw logs for the oyster market on the chain between a range and group them by block/checkpoint/slot
    fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> impl Future<Output = Result<BTreeMap<u64, Vec<Self::RawLog>>>> + Send;
}

// Transform raw logs from a block into suitable DB records
pub(crate) fn transform_block_logs_into_records(
    provider: &str,
    logs: &[impl FromLog],
    active_jobs: &mut HashSet<String>,
) -> Result<Vec<JobEventRecord>> {
    let mut job_event_records = vec![];

    for log in logs.iter() {
        let Some(job_event) = log
            .to_job_event()
            .context("Failed to parse raw log into DB record")?
        else {
            continue;
        };

        match job_event {
            JobEvent::Opened(event) => {
                // Check if provider matches the target
                if !event.provider.eq_ignore_ascii_case(provider) {
                    continue;
                }

                active_jobs.insert(event.job_id.clone());
                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::Opened,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobOpened event data for DB record")?,
                });
            }
            JobEvent::Closed(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                active_jobs.remove(&event.job_id);
                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::Closed,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobClosed event data for DB record")?,
                });
            }
            JobEvent::Settled(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::Settled,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobSettled event data for DB record")?,
                });
            }
            JobEvent::Deposited(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::Deposited,
                    event_data: serde_json::to_value(event).context(
                        "Failed to JSON serialize JobDeposited event data for DB record",
                    )?,
                });
            }
            JobEvent::Withdrew(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::Withdrew,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobWithdrew event data for DB record")?,
                });
            }
            JobEvent::ReviseRateInitiated(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::ReviseRateInitiated,
                    event_data: serde_json::to_value(event).context(
                        "Failed to JSON serialize JobReviseRateInitiated event data for DB record",
                    )?,
                });
            }
            JobEvent::ReviseRateCancelled(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::ReviseRateCancelled,
                    event_data: serde_json::to_value(event).context(
                        "Failed to JSON serialize JobReviseRateCancelled event data for DB record",
                    )?,
                });
            }
            JobEvent::ReviseRateFinalized(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::ReviseRateFinalized,
                    event_data: serde_json::to_value(event).context(
                        "Failed to JSON serialize JobReviseRateFinalized event data for DB record",
                    )?,
                });
            }
            JobEvent::MetadataUpdated(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id.clone(),
                    event_name: JobEventName::MetadataUpdated,
                    event_data: serde_json::to_value(event).context(
                        "Failed to JSON serialize JobMetadataUpdated event data for DB record",
                    )?,
                });
            }
        };
    }

    Ok(job_event_records)
}
