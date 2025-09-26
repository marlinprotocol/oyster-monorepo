use serde_json::Value;
use sqlx::prelude::FromRow;
use sqlx::types::chrono::{DateTime, Utc};

/// A structured representation of the data to be inserted into the `job_events` table
#[derive(Clone, Debug, FromRow)]
pub struct JobEventRecord {
    pub block_id: i64,
    pub tx_hash: String,
    pub event_seq: i64,
    pub block_timestamp: DateTime<Utc>,
    pub sender: String,
    pub event_name: String,
    pub event_data: Value,
    pub job_id: String,
}
