use crate::provider::ParsedSuiLog;
use alloy::primitives::U256;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::sql_types::Numeric;
use diesel::sql_types::Timestamp;
use diesel::ExpressionMethods;
use diesel::IntoSql;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::revise_rate_requests;
use serde::Deserialize;
use std::str::FromStr;
use tracing::{info, instrument, warn};

/// Sui LockCreated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LockCreatedEvent {
    pub selector: Vec<u8>,
    pub key: Vec<u8>,
    /// u256 is represented as 32 bytes in little-endian format
    pub i_value: [u8; 32],
    pub unlock_time: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_lock_created(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: LockCreatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode LockCreated event data")?;

    // Convert key (job_id) to hex string with 0x prefix
    // The key is the job_id as bytes
    let id = format!("0x{}", hex::encode(&event.key));

    // Convert i_value (u256 in little-endian) to BigDecimal
    // For rate revision, this is the new rate value
    let value = u256_le_to_bigdecimal(&event.i_value);

    // unlock_time is already in seconds
    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(event.unlock_time);

    // we want to insert if request does not exist and job exists and is not closed
    // we want to error out if request already exists or job does not exist or is closed

    info!(id, ?value, ?timestamp, "creating revise rate request");

    // target sql:
    // INSERT INTO revise_rate_requests (id, value, updates_at)
    // SELECT id, "<value>", "<timestamp>"
    // FROM jobs
    // WHERE jobs.is_closed = false
    // AND id = "<id>";
    let count = diesel::insert_into(revise_rate_requests::table)
        .values(
            // we want to detect if the job exists and is not closed
            // we do it by using INSERT INTO ... SELECT ... WHERE ...
            // the INSERT happens if SELECT returns something
            // which happens only if the WHERE conditions match
            // the rest of the values are just piped through SELECT
            jobs::table
                .select((
                    jobs::id,
                    value.as_sql::<Numeric>(),
                    timestamp.as_sql::<Timestamp>(),
                ))
                .filter(jobs::is_closed.eq(false))
                .filter(jobs::id.eq(&id)),
        )
        .execute(conn)
        .context("failed to create revise rate request")?;

    if count != 1 {
        // This can happen if:
        // 1. The job doesn't exist (not indexed yet or different ID format)
        // 2. The job is closed
        // 3. A revise rate request already exists for this job
        // Log a warning and continue instead of erroring
        warn!(id, ?value, ?timestamp);
        return Err(anyhow::anyhow!(
            "could not create revise rate request - job may not exist or is closed"
        ));
    }

    info!(id, ?value, ?timestamp, "created revise rate request");

    Ok(())
}

/// Convert a u256 in little-endian byte format to BigDecimal
fn u256_le_to_bigdecimal(bytes: &[u8; 32]) -> BigDecimal {
    // Convert little-endian bytes to U256
    let value = U256::from_le_bytes(*bytes);

    // Convert to string and then to BigDecimal
    BigDecimal::from_str(&value.to_string()).unwrap_or_else(|_| BigDecimal::from(0))
}
