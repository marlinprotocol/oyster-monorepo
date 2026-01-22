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

#[cfg(test)]
mod tests {
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::*;
    use anyhow::Context;
    use anyhow::Result;
    use bigdecimal::BigDecimal;
    use diesel::ExpressionMethods;
    use diesel::QueryDsl;
    use diesel::RunQueryDsl;
    use indexer_framework::schema::jobs;
    use indexer_framework::schema::transactions;
    use sui_sdk_types::Address;

    // ------------------------------------------------------------------------
    // Test: Depositing into an existing active job
    // Expected: Balance and end_epoch should increase, transaction recorded
    // ------------------------------------------------------------------------
    #[test]
    fn test_deposit_existing_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let original_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x00000000000000000000000000000001"),
                jobs::owner
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                jobs::provider
                    .eq("0x0202020202020202020202020202020202020202020202020202020202020202"),
                jobs::metadata.eq("original-metadata-1"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp + (10000 / 100))),
            ))
            .execute(conn)
            .context("failed to create job")?;
        let creation_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let creation_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(creation_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x00000000000000000000000000000002"),
                jobs::owner
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                jobs::provider
                    .eq("0x0202020202020202020202020202020202020202020202020202020202020202"),
                jobs::metadata.eq("original-metadata-2"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (10000 / 100))),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(1000),
                transactions::idx.eq(0),
                transactions::tx_hash.eq("DigestABC123xyz789test1"),
                transactions::job.eq("0x00000000000000000000000000000001"),
                transactions::amount.eq(BigDecimal::from(5000)),
                transactions::is_deposit.eq(false),
            ))
            .execute(conn)
            .context("failed to create job")?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "original-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "original-metadata-2".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (10000 / 100)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .first(conn),
            Ok((
                1000i64,
                0i64,
                "DigestABC123xyz789test1".to_owned(),
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(5000),
                false,
            ))
        );

        // Deposit into the job
        let bcs_data = encode_job_deposited_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            5000,
        );
        let log = TestSuiLog::new("JobDeposited", "DigestABC123xyz789test2", 1001, bcs_data)
            .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
        handle_log(conn, log, &provider).unwrap();

        // Verify counts after
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        // Verify job with all columns
        // balance: 10000 + 5000 = 15000, end_epoch: original_timestamp + (10000 / 100) + (5000 / 100) = 1704067350
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "original-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(15000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100) + (5000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "original-metadata-2".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (10000 / 100)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(2));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by(transactions::block)
                .load(conn),
            Ok(vec![
                (
                    1000i64,
                    0i64,
                    "DigestABC123xyz789test1".to_owned(),
                    "0x00000000000000000000000000000001".to_owned(),
                    BigDecimal::from(5000),
                    false,
                ),
                (
                    1001i64,
                    0i64,
                    "DigestABC123xyz789test2".to_owned(),
                    "0x00000000000000000000000000000001".to_owned(),
                    BigDecimal::from(5000),
                    true,
                ),
            ])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Depositing into a nonexistent job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_deposit_nonexistent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        // Verify initial state
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(transactions::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_deposited_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            5000,
        );
        let log = TestSuiLog::new("JobDeposited", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        let provider = MockProvider::new(0);
        let result = handle_log(conn, log, &provider);
        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            "failed to find rate for job"
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(transactions::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Depositing into a closed job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_deposit_closed_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let original_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x00000000000000000000000000000001"),
                jobs::owner
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                jobs::provider
                    .eq("0x0202020202020202020202020202020202020202020202020202020202020202"),
                jobs::metadata.eq("original-metadata-1"),
                jobs::rate.eq(BigDecimal::from(0)),
                jobs::balance.eq(BigDecimal::from(0)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(true),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp)),
            ))
            .execute(conn)
            .context("failed to create job")?;

        // Verify initial state
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "original-metadata-1".to_owned(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                BigDecimal::from(0),
                BigDecimal::from(0),
                original_now,
                original_now,
                true,
                BigDecimal::from(original_timestamp),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_deposited_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            5000,
        );
        let log = TestSuiLog::new("JobDeposited", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();
        let provider = MockProvider::new(original_timestamp);
        let result = handle_log(conn, log, &provider);

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            "failed to find rate for job"
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "original-metadata-1".to_owned(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                BigDecimal::from(0),
                BigDecimal::from(0),
                original_now,
                original_now,
                true,
                BigDecimal::from(original_timestamp),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
