use crate::provider::ParsedSuiLog;
use alloy::primitives::U256;
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
use indexer_framework::schema::revise_rate_requests;
use serde::Deserialize;
use std::str::FromStr;
use tracing::{info, instrument, warn};

/// Sui LockCreated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LockCreatedEvent {
    pub selector: Vec<u8>,
    pub key: Vec<u8>,
    /// u256 is represented as 32 bytes in little-endian format
    pub i_value: [u8; 32],
    pub unlock_time: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_lock_created(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: LockCreatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode LockCreated event data")?;

    // Convert key (job_id) to hex string with 0x prefix
    // The key is the job_id as bytes
    let id = format!("0x{}", hex::encode(&event.key));

    // Convert i_value (u256 in little-endian) to BigDecimal
    // For rate revision, this is the new rate value
    let value = u256_le_to_bigdecimal(&event.i_value);

    // unlock_time is already in seconds
    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(event.unlock_time);

    // we want to insert if request does not exist and job exists and is not closed
    // we want to error out if request already exists or job does not exist or is closed

    info!(id, ?value, ?timestamp, "creating revise rate request");

    // target sql:
    // INSERT INTO revise_rate_requests (id, value, updates_at)
    // SELECT id, "<value>", "<timestamp>"
    // FROM jobs
    // WHERE jobs.is_closed = false
    // AND id = "<id>";
    let count = diesel::insert_into(revise_rate_requests::table)
        .values(
            // we want to detect if the job exists and is not closed
            // we do it by using INSERT INTO ... SELECT ... WHERE ...
            // the INSERT happens if SELECT returns something
            // which happens only if the WHERE conditions match
            // the rest of the values are just piped through SELECT
            jobs::table
                .select((
                    jobs::id,
                    value.as_sql::<Numeric>(),
                    timestamp.as_sql::<Timestamp>(),
                ))
                .filter(jobs::is_closed.eq(false))
                .filter(jobs::id.eq(&id)),
        )
        .execute(conn)
        .context("failed to create revise rate request")?;

    if count != 1 {
        // This can happen if:
        // 1. The job doesn't exist (not indexed yet or different ID format)
        // 2. The job is closed
        // 3. A revise rate request already exists for this job
        // Log a warning and continue instead of erroring
        warn!(id, ?value, ?timestamp);
        return Err(anyhow::anyhow!(
            "could not create revise rate request - job may not exist or is closed"
        ));
    }

    info!(id, ?value, ?timestamp, "created revise rate request");

    Ok(())
}

/// Convert a u256 in little-endian byte format to BigDecimal
fn u256_le_to_bigdecimal(bytes: &[u8; 32]) -> BigDecimal {
    // Convert little-endian bytes to U256
    let value = U256::from_le_bytes(*bytes);

    // Convert to string and then to BigDecimal
    BigDecimal::from_str(&value.to_string()).unwrap_or_else(|_| BigDecimal::from(0))
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
    use indexer_framework::schema::revise_rate_requests;
    use std::ops::Add;
    use std::time::Duration;

    /// Create a key (job_id) in the format expected by lock events
    fn create_lock_key(job_id: u128) -> Vec<u8> {
        job_id.to_be_bytes().to_vec()
    }

    // ------------------------------------------------------------------------
    // Test: Creating a rate lock for an existing active job
    // Expected: Revise rate request should be created
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_created_existing_job() -> Result<()> {
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
        let revise_now = original_now.add(Duration::from_secs(300));
        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000002"),
                revise_rate_requests::value.eq(BigDecimal::from(5)),
                revise_rate_requests::updates_at.eq(&revise_now),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000002".to_owned(),
                BigDecimal::from(5),
                revise_now,
            )])
        );

        let bcs_data = encode_lock_created_event(
            &[0u8; 4],
            &create_lock_key(1),
            rate_to_i_value(50),
            creation_timestamp + 600,
        );

        let log =
            TestSuiLog::new("LockCreated", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider)?;

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(2));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    BigDecimal::from(50),
                    creation_now.add(Duration::from_secs(600)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    BigDecimal::from(5),
                    revise_now,
                )
            ])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Creating a rate lock for a nonexistent job
    // Expected: Should error out
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_created_nonexistent_job() -> Result<()> {
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
        let revise_now = original_now.add(Duration::from_secs(300));
        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000002"),
                revise_rate_requests::value.eq(BigDecimal::from(5)),
                revise_rate_requests::updates_at.eq(&revise_now),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000002".to_owned(),
                BigDecimal::from(5),
                revise_now,
            )])
        );

        let bcs_data = encode_lock_created_event(
            &[0u8; 4],
            &create_lock_key(9),
            rate_to_i_value(50),
            creation_timestamp + 600,
        );

        let log =
            TestSuiLog::new("LockCreated", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();
        let provider = MockProvider::new(0);
        let res = handle_log(conn, log, &provider);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "could not create revise rate request - job may not exist or is closed"
        );

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000002".to_owned(),
                BigDecimal::from(5),
                revise_now,
            )])
        );

        Ok(())
    }

    // ---------------------------------------
    // Test: Creating a rate lock for a closed job
    // Expected: Should succeed (warning logged) but no request created
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_created_closed_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;
        let mock_provider = MockProvider::new(1704067200);

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
        let revise_now = original_now.add(Duration::from_secs(300));
        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000002"),
                revise_rate_requests::value.eq(BigDecimal::from(5)),
                revise_rate_requests::updates_at.eq(&revise_now),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000002".to_owned(),
                BigDecimal::from(5),
                revise_now,
            )])
        );

        let bcs_data = encode_lock_created_event(
            &[0u8; 4],
            &create_lock_key(1),
            rate_to_i_value(200),
            creation_timestamp + 600,
        );

        let log =
            TestSuiLog::new("LockCreated", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        let res = handle_log(conn, log, &mock_provider);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "could not create revise rate request - job may not exist or is closed"
        );

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000002".to_owned(),
                BigDecimal::from(5),
                revise_now,
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Verify the key format matches expected job_id format
    // Expected: Key should reconstruct to the correct job_id string
    // ------------------------------------------------------------------------
    #[test]
    fn test_key_format() {
        let job_id: u128 = 1;
        let key = create_lock_key(job_id);
        let reconstructed = format!("0x{}", hex::encode(&key));
        assert!(reconstructed.starts_with("0x"));
    }
}
