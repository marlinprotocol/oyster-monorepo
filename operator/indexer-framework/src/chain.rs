use anyhow::Result;
use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use crate::events::JobEvent;
use crate::schema::JobEventRecord;

// Define trait for conversion
pub trait FromLog: Sized {
    fn from_log(&self) -> Result<Option<JobEvent>>;
}

/// Trait every chain must implement
pub trait ChainHandler {
    type RawLog: FromLog;

    fn fetch_latest_block(&self) -> impl Future<Output = Result<u64>> + Send;
    fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> impl Future<Output = Result<BTreeMap<u64, Vec<Self::RawLog>>>> + Send;
    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &Vec<Self::RawLog>,
        active_jobs: &mut HashSet<String>,
    ) -> Result<Vec<JobEventRecord>>;
}
