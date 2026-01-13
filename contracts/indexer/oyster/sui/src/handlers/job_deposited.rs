use std::ops::Add;

use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::transactions;
use serde::Deserialize;
use sui_sdk_types::Address;
use tracing::{info, instrument};

/// Sui JobDeposited event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobDepositedEvent {
    pub job_id: u128,
    pub owner: Address,
    pub amount: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_deposited(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobDepositedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobDeposited event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let owner = event.owner.to_string();
    let amount = BigDecimal::from(event.amount);

    let block = parsed.checkpoint;
    let idx = 0i64; // Sui doesn't have log index like EVM
    let tx_hash = parsed.tx_digest;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed
    info!(id, owner, ?amount, "depositing into job");

    // get the current rate of the job to calculate how much more time the job will run for
    // target sql:
    // SELECT rate FROM jobs
    // WHERE id = "<id>" AND is_closed = false;
    let rate = jobs::table
        .filter(jobs::id.eq(&id))
        .filter(jobs::is_closed.eq(false))
        .select(jobs::rate)
        .get_result::<BigDecimal>(conn);

    if rate.is_err() {
        // !!! should never happen
        // the only reason this would happen is if the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("failed to find rate for job"));
    }

    let rate = rate.unwrap();

    // Calculate additional duration: amount / rate (no scaling factor for Sui)
    let additional_duration = if rate != BigDecimal::from(0) {
        (&amount / &rate).round(0)
    } else {
        BigDecimal::from(0)
    };

    info!(
        id,
        ?rate,
        ?additional_duration,
        "got job rate and additional duration"
    );

    // target sql:
    // UPDATE jobs
    // SET balance = balance + <amount>, end_epoch = end_epoch + <additional_duration>
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((
            jobs::balance.eq(jobs::balance.add(&amount)),
            jobs::end_epoch.eq(jobs::end_epoch.add(&additional_duration)),
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
    // INSERT INTO transactions (block, idx, tx_hash, job, amount, is_deposit)
    // VALUES (block, idx, "<tx_hash>", "<job>", "<amount>", true);
    diesel::insert_into(transactions::table)
        .values((
            transactions::block.eq(block as i64),
            transactions::idx.eq(idx),
            transactions::tx_hash.eq(tx_hash),
            transactions::job.eq(&id),
            transactions::amount.eq(&amount),
            transactions::is_deposit.eq(true),
        ))
        .execute(conn)
        .context("failed to create deposit")?;

    info!(id, owner, ?amount, block, "deposited into job");

    Ok(())
}
