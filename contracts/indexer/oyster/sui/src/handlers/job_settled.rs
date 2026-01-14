use std::ops::Sub;

use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::settlement_history;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobSettled event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobSettledEvent {
    pub job_id: u128,
    pub amount: u64,
    pub settled_until: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_settled(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobSettledEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobSettled event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let amount = BigDecimal::from(event.amount);

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(event.settled_until);
    let timestamp_epoch = BigDecimal::from(event.settled_until);

    let block = parsed.checkpoint;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(
        id,
        ?amount,
        ?timestamp_epoch,
        ?timestamp,
        ?block,
        "settling job"
    );

    // target sql:
    // UPDATE jobs
    // SET
    //     balance = balance - <amount>
    //     last_settled = <timestamp>
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((
            jobs::balance.eq(jobs::balance.sub(&amount)),
            jobs::last_settled.eq(&timestamp),
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

    diesel::insert_into(settlement_history::table)
        .values((
            settlement_history::id.eq(&id),
            settlement_history::amount.eq(&amount),
            settlement_history::timestamp.eq(timestamp_epoch),
            settlement_history::block.eq(block as i64),
        ))
        .execute(conn)
        .context("failed to insert settlement history")?;

    info!(id, ?amount, ?timestamp, "settled job");

    Ok(())
}
