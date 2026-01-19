use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::revise_rate_requests;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui LockDeleted event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LockDeletedEvent {
    pub selector: Vec<u8>,
    pub key: Vec<u8>,
    /// u256 is represented as 32 bytes in little-endian format
    pub i_value: [u8; 32],
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_lock_deleted(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: LockDeletedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode LockDeleted event data")?;

    // Convert key (job_id) to hex string with 0x prefix
    // The key is the job_id as bytes
    let id = format!("0x{}", hex::encode(&event.key));

    info!(id, "deleting revise rate request");

    // we want to delete if request exists
    // we want to silently ignore if request does not exist

    // target sql:
    // DELETE FROM revise_rate_requests
    // WHERE id = "<id>";
    diesel::delete(revise_rate_requests::table)
        .filter(revise_rate_requests::id.eq(&id))
        .execute(conn)
        .context("failed to delete revise rate request")?;

    // !!! closing a job emits _two_ LockDeleted events
    // cannot really check count at this point

    info!(id, "deleted revise rate request");

    Ok(())
}
