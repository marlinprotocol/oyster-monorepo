use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobClosed event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobClosedEvent {
    pub job_id: u128,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_closed(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobClosedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobClosed event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let block = parsed.checkpoint;

    // For Sui, we use the checkpoint number as the block timestamp proxy
    // In a real scenario, you might want to fetch the actual checkpoint timestamp
    // For now, we use current time as a reasonable approximation
    let block_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, ?block, ?block_timestamp, "closing job");

    // target sql:
    // UPDATE jobs
    // SET is_closed = true, rate = 0, balance = 0, end_epoch = block_timestamp
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((
            jobs::is_closed.eq(true),
            jobs::rate.eq(BigDecimal::from(0)),
            jobs::balance.eq(BigDecimal::from(0)),
            jobs::end_epoch.eq(BigDecimal::from(block_timestamp)),
        ))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    // target sql:
    // INSERT INTO rate_revisions (job_id, value, block, timestamp)
    // VALUES ("<id>", 0, "<block>", "<block_timestamp>");
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job_id.eq(&id),
            rate_revisions::value.eq(&BigDecimal::from(0)),
            rate_revisions::block.eq(block as i64),
            rate_revisions::timestamp.eq(BigDecimal::from(block_timestamp)),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(id, ?block, "closed job");

    Ok(())
}
