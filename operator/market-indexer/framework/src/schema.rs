use serde_json::Value;
use sqlx::Type;
use sqlx::prelude::FromRow;

/// A structured representation of the data to be inserted into the `job_events` table
#[derive(Clone, Debug, FromRow)]
pub struct JobEventRecord {
    pub job_id: String,
    pub event_name: JobEventName,
    pub event_data: Value,
}

#[derive(Clone, Debug, Type)]
#[sqlx(type_name = "event_name", rename_all = "PascalCase")]
pub enum JobEventName {
    Opened,
    Closed,
    Deposited,
    Settled,
    MetadataUpdated,
    Withdrew,
    ReviseRateInitiated,
    ReviseRateCancelled,
    ReviseRateFinalized,
}
