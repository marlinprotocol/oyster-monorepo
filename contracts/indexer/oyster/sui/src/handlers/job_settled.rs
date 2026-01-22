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
    use indexer_framework::schema::settlement_history;

    // ------------------------------------------------------------------------
    // Test: Settling an existing active job
    // Expected: Balance should decrease and last_settled should update
    // ------------------------------------------------------------------------
    #[test]
    fn test_settle_existing_job() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata-1"),
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
                jobs::metadata.eq("test-job-metadata-2"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (10000 / 100))),
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
                    "test-job-metadata-1".to_owned(),
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
                    "test-job-metadata-2".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100)),
                )
            ])
        );

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        let timestamp = creation_timestamp + 5;
        // we do this after the timestamp to truncate beyond seconds
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let bcs_data = encode_job_settled_event(1, 500, timestamp);
        let log =
            TestSuiLog::new("JobSettled", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider)?;

        // Verify counts after
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "test-job-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(9500),
                    now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "test-job-metadata-2".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100)),
                )
            ])
        );

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(1));

        assert_eq!(
            settlement_history::table
                .select(settlement_history::all_columns)
                .order_by(settlement_history::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(500),
                BigDecimal::from(timestamp),
                1000 as i64,
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Settling with zero amount
    // Expected: Balance should remain same, but last_settled should update
    // ------------------------------------------------------------------------
    #[test]
    fn test_settle_existing_job_with_zero_amount() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata-1"),
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
                jobs::metadata.eq("test-job-metadata-2"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (10000 / 100))),
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
                    "test-job-metadata-1".to_owned(),
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
                    "test-job-metadata-2".to_owned(),
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

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        let timestamp = original_timestamp + 5;
        // we do this after the timestamp to truncate beyond seconds
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let bcs_data = encode_job_settled_event(1, 0, timestamp);
        let log =
            TestSuiLog::new("JobSettled", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider)?;

        // Verify counts after
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "test-job-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "test-job-metadata-2".to_owned(),
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

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(1));

        assert_eq!(
            settlement_history::table
                .select(settlement_history::all_columns)
                .order_by(settlement_history::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                BigDecimal::from(timestamp),
                1000 as i64,
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Settling a nonexistent job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_settle_nonexistent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        let timestamp = original_timestamp + 5;
        // we do this after the timestamp to truncate beyond seconds
        let bcs_data = encode_job_settled_event(1, 500, timestamp);
        let log =
            TestSuiLog::new("JobSettled", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        let res = handle_log(conn, log, &provider);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Settling a closed job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_settle_closed_job() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata-1"),
                jobs::rate.eq(BigDecimal::from(0)),
                jobs::balance.eq(BigDecimal::from(0)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(true),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp)),
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
                jobs::metadata.eq("test-job-metadata-2"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (10000 / 100))),
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
                    "test-job-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(0),
                    BigDecimal::from(0),
                    original_now,
                    original_now,
                    true,
                    BigDecimal::from(original_timestamp),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "test-job-metadata-2".to_owned(),
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

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        let timestamp = original_timestamp + 5;
        // we do this after the timestamp to truncate beyond seconds
        let bcs_data = encode_job_settled_event(1, 500, timestamp);
        let log =
            TestSuiLog::new("JobSettled", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        let provider = MockProvider::new(0);
        let result = handle_log(conn, log, &provider);
        assert_eq!(format!("{:?}", result.unwrap_err()), "could not find job");

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "test-job-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(0),
                    BigDecimal::from(0),
                    original_now,
                    original_now,
                    true,
                    BigDecimal::from(original_timestamp),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "test-job-metadata-2".to_owned(),
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

        assert_eq!(settlement_history::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
