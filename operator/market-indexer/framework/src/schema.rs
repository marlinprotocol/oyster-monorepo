use serde_json::Value;
use sqlx::prelude::FromRow;

/// A structured representation of the data to be inserted into the `job_events` table
#[derive(Clone, Debug, FromRow)]
pub struct JobEventRecord {
    pub job_id: String,
    pub event_name: String,
    pub event_data: Value,
}
