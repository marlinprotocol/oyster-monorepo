use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

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

// Serialize event data for the JSONB column
// Postgres rejects the NUL character in JSONB (and TEXT) values while chains allow it in
// strings like job metadata, one such event would fail every insert of its batch and
// stall the indexer on that block for good, hence NULs are dropped from all strings
fn to_event_data(event: &impl Serialize) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(event)?;
    strip_nul(&mut value);
    Ok(value)
}

fn strip_nul(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s.contains('\0') {
                s.retain(|c| c != '\0');
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_nul),
        Value::Object(fields) => fields.values_mut().for_each(strip_nul),
        _ => {}
    }
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
                    event_data: to_event_data(&event)
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
                    event_data: to_event_data(&event)
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
                    event_data: to_event_data(&event)
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
                    event_data: to_event_data(&event).context(
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
                    event_data: to_event_data(&event)
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
                    event_data: to_event_data(&event).context(
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
                    event_data: to_event_data(&event).context(
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
                    event_data: to_event_data(&event).context(
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
                    event_data: to_event_data(&event).context(
                        "Failed to JSON serialize JobMetadataUpdated event data for DB record",
                    )?,
                });
            }
        };
    }

    Ok(job_event_records)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use alloy_primitives::U256;
    use anyhow::Result;

    use super::{FromLog, transform_block_logs_into_records};
    use crate::events::{JobEvent, JobMetadataUpdated, JobOpened};

    const JOB: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    const PROVIDER: &str = "0x00000000000000000000000000000000000000aa";

    enum TestLog {
        Opened(&'static str),
        MetadataUpdated(&'static str),
    }

    impl FromLog for TestLog {
        fn to_job_event(&self) -> Result<Option<JobEvent>> {
            Ok(Some(match self {
                TestLog::Opened(metadata) => JobEvent::Opened(JobOpened {
                    job_id: JOB.to_owned(),
                    owner: "0x00000000000000000000000000000000000000bb".to_owned(),
                    provider: PROVIDER.to_owned(),
                    metadata: (*metadata).to_owned(),
                    rate: U256::from(1),
                    balance: U256::from(2),
                    timestamp: 3,
                }),
                TestLog::MetadataUpdated(metadata) => {
                    JobEvent::MetadataUpdated(JobMetadataUpdated {
                        job_id: JOB.to_owned(),
                        new_metadata: (*metadata).to_owned(),
                    })
                }
            }))
        }
    }

    #[test]
    fn nul_in_metadata_is_dropped() {
        let logs = [
            TestLog::Opened("{\"url\":\"a\0b\"}\0"),
            TestLog::MetadataUpdated("\0\0"),
            TestLog::MetadataUpdated("plain"),
        ];
        let mut active_jobs = HashSet::new();

        let records = transform_block_logs_into_records(PROVIDER, &logs, &mut active_jobs).unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].event_data["metadata"], "{\"url\":\"ab\"}");
        assert_eq!(records[1].event_data["new_metadata"], "");
        assert_eq!(records[2].event_data["new_metadata"], "plain");

        // what gets sent to postgres must not have the escape it rejects
        for record in &records {
            let text = serde_json::to_string(&record.event_data).unwrap();
            assert!(!text.contains("\\u0000"), "{text}");
        }

        // rest of the event is untouched
        assert_eq!(records[0].event_data["job_id"], JOB);
        assert_eq!(records[0].event_data["timestamp"], 3);
    }
}
