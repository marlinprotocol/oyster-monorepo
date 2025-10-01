use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use anyhow::{Context, Result};

use crate::events::JobEvent;
use crate::schema::JobEventRecord;

// Define trait for conversion from raw log to structured JobEvent
pub trait FromLog: Sized {
    fn to_job_event(&self) -> Result<Option<JobEvent>>;
}

/// Trait every chain must implement
pub trait ChainHandler {
    type RawLog: FromLog;

    /// Fetch latest block/checkpoint/slot for the chain
    fn fetch_latest_block(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Fetch raw logs for the oyster market on the chain between a range and group them by block/checkpoint/slot
    fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> impl Future<Output = Result<BTreeMap<u64, Vec<Self::RawLog>>>> + Send;

    // Transform raw logs from a block into suitable DB records
    fn transform_block_logs_into_records(
        &self,
        provider: &str,
        logs: &[Self::RawLog],
        active_jobs: &mut HashSet<String>,
    ) -> Result<Vec<JobEventRecord>> {
        let mut job_event_records = vec![];

        for log in logs.iter() {
            let Some(job_event) = log
                .to_job_event()
                .context("Failed to parse log into event structure")?
            else {
                continue;
            };

            match job_event {
                JobEvent::Opened(event) => {
                    // Check if provider matches the target
                    if event.provider != provider {
                        continue;
                    }

                    active_jobs.insert(event.job_id.clone());
                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobOpened".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobOpened event data")?,
                    });
                }
                JobEvent::Closed(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    active_jobs.remove(&event.job_id);
                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobClosed".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobClosed event data")?,
                    });
                }
                JobEvent::Settled(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobSettled".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobSettled event data")?,
                    });
                }
                JobEvent::Deposited(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobDeposited".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobDeposited event data")?,
                    });
                }
                JobEvent::Withdrew(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobWithdrew".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobWithdrew event data")?,
                    });
                }
                JobEvent::ReviseRateInitiated(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobReviseRateInitiated".to_string(),
                        event_data: serde_json::to_value(event).context(
                            "Failed to JSON serialize JobReviseRateInitiated event data",
                        )?,
                    });
                }
                JobEvent::ReviseRateCancelled(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobReviseRateCancelled".to_string(),
                        event_data: serde_json::to_value(event).context(
                            "Failed to JSON serialize JobReviseRateCancelled event data",
                        )?,
                    });
                }
                JobEvent::ReviseRateFinalized(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobReviseRateFinalized".to_string(),
                        event_data: serde_json::to_value(event).context(
                            "Failed to JSON serialize JobReviseRateFinalized event data",
                        )?,
                    });
                }
                JobEvent::MetadataUpdated(event) => {
                    if !active_jobs.contains(&event.job_id) {
                        continue;
                    }

                    job_event_records.push(JobEventRecord {
                        job_id: event.job_id.clone(),
                        event_name: "JobMetadataUpdated".to_string(),
                        event_data: serde_json::to_value(event)
                            .context("Failed to JSON serialize JobMetadataUpdated event data")?,
                    });
                }
            };
        }

        Ok(job_event_records)
    }
}
