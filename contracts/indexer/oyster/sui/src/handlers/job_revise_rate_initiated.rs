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
use indexer_framework::schema::lock_duration;
use indexer_framework::schema::revise_rate_requests;
use indexer_framework::LogsProvider;
use serde::Deserialize;
use tracing::{info, instrument};

use crate::provider::ParsedSuiLog;

/// Sui JobReviseRateInitiated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobReviseRateInitiatedEvent {
    pub job_id: u128,
    pub new_rate: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_initiated(
    conn: &mut PgConnection,
    parsed: &ParsedSuiLog,
    provider: &impl LogsProvider,
) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobReviseRateInitiatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobReviseRateInitiated event data")?;

    let id = format!("0x{:032x}", event.job_id);
    let new_rate = BigDecimal::from(event.new_rate);
    // Fetch the block timestamp from the RPC
    let block = parsed.checkpoint;
    let block_timestamp = provider.block_timestamp(block)?;

    let lock_duration = lock_duration::table
        .select(lock_duration::duration)
        .get_result::<BigDecimal>(conn)
        .context("failed to get lock duration")?;

    let updates_at_epoch = &block_timestamp + &lock_duration;
    let updates_at = std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs(updates_at_epoch.round(0).to_string().parse::<u64>()?);

    info!(
        id,
        ?new_rate,
        ?block,
        ?block_timestamp,
        ?updates_at_epoch,
        ?updates_at,
        ?lock_duration,
        "initiating job rate revision"
    );

    // we want to insert if request for a rate revision does not exist, the job exists and is not closed
    // we want to error out if request for a rate revision already exists, the job does not exist or is closed

    // target sql:
    // INSERT INTO revise_rate_requests (id, value, updates_at)
    // SELECT id, "<new_rate>", "<block_timestamp>"
    // FROM jobs
    // WHERE jobs.is_closed = false
    // AND id = "<id>";
    let count = diesel::insert_into(revise_rate_requests::table)
        .values(
            // we want to detect if the provider exists and is active
            // we do it by using INSERT INTO ... SELECT ... WHERE ...
            // the INSERT happens if SELECT returns something
            // which happens only if the WHERE conditions match
            // the rest of the values are just piped through SELECT
            jobs::table
                .select((
                    jobs::id,
                    new_rate.as_sql::<Numeric>(),
                    updates_at.as_sql::<Timestamp>(),
                    updates_at_epoch.as_sql::<Numeric>(),
                ))
                .filter(jobs::is_closed.eq(false))
                .filter(jobs::id.eq(&id)),
        )
        .execute(conn)
        .context("failed to initiate job rate revision")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the request for a rate revision already exists or
        // the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!(
            "did not expect to find a non existent request or closed job"
        ));
    }

    info!(
        id,
        ?new_rate,
        ?block,
        ?block_timestamp,
        ?updates_at_epoch,
        ?updates_at,
        ?lock_duration,
        "initiated job rate revision"
    );

    Ok(())
}
