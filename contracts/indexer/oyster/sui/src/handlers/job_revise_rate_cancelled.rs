use crate::provider::ParsedSuiLog;
use anyhow::{Context, Result};
use diesel::{ExpressionMethods, PgConnection, RunQueryDsl};
use indexer_framework::schema::revise_rate_requests;
use serde::Deserialize;
use tracing::{info, instrument, warn};

/// Sui JobReviseRateCancelled event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobReviseRateCancelledEvent {
    pub job_id: u128,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_cancelled(
    conn: &mut PgConnection,
    parsed: &ParsedSuiLog,
) -> Result<()> {
    let event: JobReviseRateCancelledEvent = bcs::from_bytes(parsed.bcs_contents)
        .context("Failed to BCS decode JobReviseRateCancelled event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);

    info!(id, "cancelling job rate revision");

    // target sql:
    // DELETE FROM revise_rate_requests
    // WHERE id = "<id>";
    let count = diesel::delete(revise_rate_requests::table)
        .filter(revise_rate_requests::id.eq(&id))
        .execute(conn)
        .context("failed to delete revise rate request")?;

    if count != 1 {
        // !!! should never happen
        // the only real condition is when the request does not exist or is already deleted
        // it is not a critical error, we can just move on
        warn!("did not expect to find a non existent request when cancelling job rate revision");
    }

    info!(id, "deleted revise rate request");

    Ok(())
}

// TODO: add tests
