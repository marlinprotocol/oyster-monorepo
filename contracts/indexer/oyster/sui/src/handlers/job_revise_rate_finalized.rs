use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobReviseRateFinalized event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobReviseRateFinalizedEvent {
    pub job_id: u128,
    pub new_rate: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_finalized(
    conn: &mut PgConnection,
    parsed: &ParsedSuiLog,
) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobReviseRateFinalizedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobReviseRateFinalized event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let rate = BigDecimal::from(event.new_rate);
    let block = parsed.checkpoint;

    // Use current time as timestamp since the event doesn't include one
    let block_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    info!(
        id,
        ?rate,
        ?block,
        ?block_timestamp,
        "finalizing job rate revision"
    );

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    // get the reduced job balance as jobs get settled when the rate is revised
    let job_balance = jobs::table
        .filter(jobs::id.eq(&id))
        .filter(jobs::is_closed.eq(false))
        .select(jobs::balance)
        .get_result::<BigDecimal>(conn)
        .context("failed to get job balance");

    if job_balance.is_err() {
        // !!! should never happen
        // the only reason this would happen is if the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("failed to find balance for job"));
    }

    let job_balance = job_balance.unwrap();
    let mut new_end_epoch = BigDecimal::from(block_timestamp);

    // Calculate new end_epoch: timestamp + (balance / rate) (no scaling factor for Sui)
    if rate != BigDecimal::from(0) {
        new_end_epoch = new_end_epoch + (&job_balance / &rate).round(0);
    }

    info!(id, ?job_balance, ?new_end_epoch, "calculated new end epoch");

    // target sql:
    // UPDATE jobs
    // SET rate = <rate>, end_epoch = <new_end_epoch>
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((jobs::rate.eq(&rate), jobs::end_epoch.eq(&new_end_epoch)))
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
    // VALUES ("<id>", "<rate>", "<block>", "<timestamp>");
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job_id.eq(&id),
            rate_revisions::value.eq(&rate),
            rate_revisions::block.eq(block as i64),
            rate_revisions::timestamp.eq(BigDecimal::from(block_timestamp)),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(id, ?rate, "finalized job rate revision");

    Ok(())
}
