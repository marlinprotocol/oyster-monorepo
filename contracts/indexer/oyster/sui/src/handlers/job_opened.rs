use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use indexer_framework::schema::transactions;
use serde::Deserialize;
use sui_sdk_types::Address;
use tracing::{info, instrument};

/// Sui JobOpened event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobOpenedEvent {
    pub job_id: u128,
    pub owner: Address,
    pub provider: Address,
    pub metadata: String,
    pub rate: u64,
    pub balance: u64,
    pub timestamp: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_opened(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobOpenedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobOpened event data")?;

    // Convert to appropriate string formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let owner = event.owner.to_string();
    let provider = event.provider.to_string();
    let metadata = event.metadata;

    // Convert rate and balance to BigDecimal
    let rate = BigDecimal::from(event.rate);
    let balance = BigDecimal::from(event.balance);

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(event.timestamp);
    let timestamp_epoch = BigDecimal::from(event.timestamp);

    let mut run_duration = BigDecimal::from(0);
    let mut end_epoch = timestamp_epoch.clone();

    if &rate != &BigDecimal::from(0) {
        run_duration = (&balance / &rate).round(0);
        end_epoch = &timestamp_epoch + &run_duration;
    }

    let block = parsed.checkpoint;
    let idx = 0i64; // Sui doesn't have log index like EVM
    let tx_hash = parsed.tx_digest;

    info!(
        id,
        owner,
        provider,
        metadata,
        ?rate,
        ?balance,
        ?timestamp,
        ?timestamp_epoch,
        block,
        run_duration = run_duration.to_string(),
        end_epoch = end_epoch.to_string(),
        "creating job"
    );

    // target sql:
    // INSERT INTO jobs (id, metadata, owner, provider, rate, balance, last_settled, created, is_closed, end_epoch)
    // VALUES ("<id>", "<metadata>", "<owner>", "<provider>", "<rate>", "<balance>", "<timestamp>", "<timestamp>", false, "<end_epoch>");
    diesel::insert_into(jobs::table)
        .values((
            jobs::id.eq(&id),
            jobs::metadata.eq(&metadata),
            jobs::owner.eq(&owner),
            jobs::provider.eq(&provider),
            jobs::rate.eq(&rate),
            jobs::balance.eq(&balance),
            jobs::last_settled.eq(&timestamp),
            jobs::created.eq(&timestamp),
            jobs::is_closed.eq(false),
            jobs::end_epoch.eq(&end_epoch),
        ))
        .execute(conn)
        .context("failed to create job")?;

    // target sql:
    // INSERT INTO transactions (block, idx, job, value, is_deposit)
    // VALUES (block, idx, "<job>", "<value>", true);
    diesel::insert_into(transactions::table)
        .values((
            transactions::block.eq(block as i64),
            transactions::idx.eq(idx),
            transactions::tx_hash.eq(tx_hash),
            transactions::job.eq(&id),
            transactions::amount.eq(&balance),
            transactions::is_deposit.eq(true),
        ))
        .execute(conn)
        .context("failed to create deposit")?;

    // target sql:
    // INSERT INTO rate_revisions (job_id, value, block, timestamp)
    // VALUES ("<id>", "<rate>", "<block>", "<timestamp>");
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job_id.eq(&id),
            rate_revisions::value.eq(&rate),
            rate_revisions::block.eq(block as i64),
            rate_revisions::timestamp.eq(&timestamp_epoch),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(
        id,
        owner,
        provider,
        metadata,
        ?rate,
        ?balance,
        ?timestamp,
        block,
        run_duration = run_duration.to_string(),
        end_epoch = end_epoch.to_string(),
        "created job"
    );

    Ok(())
}
