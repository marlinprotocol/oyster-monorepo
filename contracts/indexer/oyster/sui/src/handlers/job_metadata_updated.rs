use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobMetadataUpdated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobMetadataUpdatedEvent {
    pub job_id: u128,
    pub new_metadata: String,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_metadata_updated(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobMetadataUpdatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobMetadataUpdated event data")?;

    // Convert job_id to hex string format
    let id = format!("0x{:032x}", event.job_id);
    let metadata = event.new_metadata;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, ?metadata, "updating job metadata");

    // target sql:
    // UPDATE jobs
    // SET metadata = "<metadata>"
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set(jobs::metadata.eq(&metadata))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    info!(id, ?metadata, "updated job metadata");

    Ok(())
}
