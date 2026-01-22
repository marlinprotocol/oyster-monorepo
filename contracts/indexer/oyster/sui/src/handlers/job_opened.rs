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
    use indexer_framework::schema::rate_revisions;
    use indexer_framework::schema::transactions;
    use sui_sdk_types::Address;

    // ------------------------------------------------------------------------
    // Test: Creating a new job in an empty database
    // Expected: Job, transaction, and rate revision should all be created
    // ------------------------------------------------------------------------
    #[test]
    fn test_new_job_empty_db() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(transactions::table.count().get_result(conn), Ok(0));
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let bcs_data = encode_job_opened_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            &"0x0202020202020202020202020202020202020202020202020202020202020202"
                .parse::<Address>()?,
            "test-job-metadata",
            100,
            10000,
            timestamp,
        );
        let log =
            TestSuiLog::new("JobOpened", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        let provider = MockProvider::new(timestamp);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                "test-job-metadata".to_string(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                now,
                now,
                false,
                BigDecimal::from(timestamp + (10000 / 100)),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .first(conn),
            Ok((
                1000i64,
                0i64,
                "DigestABC123xyz789test".to_string(),
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(10000),
                true,
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(100),
                1000i64,
                BigDecimal::from(timestamp)
            ))
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Creating a new job in a populated database
    // Expected: Job should be created without affecting other jobs
    // ------------------------------------------------------------------------
    #[test]
    fn test_new_job_populated_db() -> Result<()> {
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

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(1000),
                transactions::idx.eq(0),
                transactions::tx_hash.eq("DigestABC123xyz789test"),
                transactions::job.eq("0x00000000000000000000000000000001"),
                transactions::amount.eq(BigDecimal::from(10000)),
                transactions::is_deposit.eq(true),
            ))
            .execute(conn)
            .context("failed to create transaction")?;

        diesel::insert_into(rate_revisions::table)
            .values((
                rate_revisions::job_id.eq("0x00000000000000000000000000000001"),
                rate_revisions::value.eq(BigDecimal::from(100)),
                rate_revisions::block.eq(1000),
                rate_revisions::timestamp.eq(BigDecimal::from(original_timestamp)),
            ))
            .execute(conn)
            .context("failed to create rate revision")?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                "test-job-metadata-1".to_string(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![(
                1000i64,
                0i64,
                "DigestABC123xyz789test".to_string(),
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(10000),
                true,
            )])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .order_by(rate_revisions::job_id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(100),
                1000i64,
                BigDecimal::from(original_timestamp),
            )])
        );

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let bcs_data_2 = encode_job_opened_event(
            2,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            &"0x0202020202020202020202020202020202020202020202020202020202020202"
                .parse::<Address>()?,
            "test-job-metadata-2",
            200,
            20000,
            timestamp,
        );
        let log_2 = TestSuiLog::new("JobOpened", "Digest2", 1000 + 1, bcs_data_2).to_alloy_log();

        let provider = MockProvider::new(timestamp);
        handle_log(conn, log_2, &provider)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_string(),
                    "test-job-metadata-1".to_string(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101"
                        .to_string(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202"
                        .to_string(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(original_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_string(),
                    "test-job-metadata-2".to_string(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101"
                        .to_string(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202"
                        .to_string(),
                    BigDecimal::from(200),
                    BigDecimal::from(20000),
                    now,
                    now,
                    false,
                    BigDecimal::from(timestamp + (20000 / 200)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(2));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![
                (
                    1000i64,
                    0i64,
                    "DigestABC123xyz789test".to_string(),
                    "0x00000000000000000000000000000001".to_string(),
                    BigDecimal::from(10000),
                    true,
                ),
                (
                    1001i64,
                    0i64,
                    "Digest2".to_string(),
                    "0x00000000000000000000000000000002".to_string(),
                    BigDecimal::from(20000),
                    true,
                )
            ])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(2));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .order_by(rate_revisions::job_id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_string(),
                    BigDecimal::from(100),
                    1000i64,
                    BigDecimal::from(original_timestamp),
                ),
                (
                    "0x00000000000000000000000000000002".to_string(),
                    BigDecimal::from(200),
                    1001i64,
                    BigDecimal::from(timestamp),
                )
            ])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Creating a job with zero rate
    // Expected: Job should be created with end_epoch equal to timestamp
    //           (no run duration when rate is zero)
    // ------------------------------------------------------------------------
    #[test]
    fn test_new_job_zero_rate() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(transactions::table.count().get_result(conn), Ok(0));
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let bcs_data = encode_job_opened_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            &"0x0202020202020202020202020202020202020202020202020202020202020202"
                .parse::<Address>()?,
            "test-job-metadata-1",
            0,
            10000,
            timestamp,
        );
        let log =
            TestSuiLog::new("JobOpened", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        let provider = MockProvider::new(timestamp);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                "test-job-metadata-1".to_string(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                BigDecimal::from(0),
                BigDecimal::from(10000),
                now,
                now,
                false,
                BigDecimal::from(timestamp),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .load(conn),
            Ok(vec![(
                1000i64,
                0i64,
                "DigestABC123xyz789test".to_string(),
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(10000),
                true,
            )])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(0),
                1000i64,
                BigDecimal::from(timestamp)
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Creating a duplicate job (same job_id)
    // Expected: Should fail due to primary key constraint
    // ------------------------------------------------------------------------
    #[test]
    fn test_duplicate_job() -> Result<()> {
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

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(1000),
                transactions::idx.eq(0),
                transactions::tx_hash.eq("DigestABC123xyz789test"),
                transactions::job.eq("0x00000000000000000000000000000001"),
                transactions::amount.eq(BigDecimal::from(10000)),
                transactions::is_deposit.eq(true),
            ))
            .execute(conn)
            .context("failed to create transaction")?;

        diesel::insert_into(rate_revisions::table)
            .values((
                rate_revisions::job_id.eq("0x00000000000000000000000000000001"),
                rate_revisions::value.eq(BigDecimal::from(100)),
                rate_revisions::block.eq(1000),
                rate_revisions::timestamp.eq(BigDecimal::from(original_timestamp)),
            ))
            .execute(conn)
            .context("failed to create rate revision")?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                "test-job-metadata-1".to_string(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![(
                1000i64,
                0i64,
                "DigestABC123xyz789test".to_string(),
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(10000),
                true,
            )])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .order_by(rate_revisions::job_id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(100),
                1000i64,
                BigDecimal::from(original_timestamp),
            )])
        );

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let bcs_data = encode_job_opened_event(
            1,
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            &"0x0202020202020202020202020202020202020202020202020202020202020202"
                .parse::<Address>()?,
            "test-job-metadata-2",
            200,
            20000,
            timestamp,
        );
        let log_2 = TestSuiLog::new("JobOpened", "Digest2", 1000 + 1, bcs_data).to_alloy_log();

        let provider = MockProvider::new(timestamp);
        let res = handle_log(conn, log_2, &provider);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to create job\n\nCaused by:\n    duplicate key value violates unique constraint \"jobs_pkey\""
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                "test-job-metadata-1".to_string(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            ),])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![(
                1000i64,
                0i64,
                "DigestABC123xyz789test".to_string(),
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(10000),
                true,
            ),])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .order_by(rate_revisions::job_id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_string(),
                BigDecimal::from(100),
                1000i64,
                BigDecimal::from(original_timestamp),
            ),])
        );

        Ok(())
    }
}
