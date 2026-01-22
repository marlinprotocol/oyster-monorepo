use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::revise_rate_requests;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui LockDeleted event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LockDeletedEvent {
    pub selector: Vec<u8>,
    pub key: Vec<u8>,
    /// u256 is represented as 32 bytes in little-endian format
    pub i_value: [u8; 32],
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_lock_deleted(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: LockDeletedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode LockDeleted event data")?;

    // Convert key (job_id) to hex string with 0x prefix
    // The key is the job_id as bytes
    let id = format!("0x{}", hex::encode(&event.key));

    info!(id, "deleting revise rate request");

    // we want to delete if request exists
    // we want to silently ignore if request does not exist

    // target sql:
    // DELETE FROM revise_rate_requests
    // WHERE id = "<id>";
    diesel::delete(revise_rate_requests::table)
        .filter(revise_rate_requests::id.eq(&id))
        .execute(conn)
        .context("failed to delete revise rate request")?;

    // !!! closing a job emits _two_ LockDeleted events
    // cannot really check count at this point

    info!(id, "deleted revise rate request");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use std::time::Duration;

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

    /// Create a key (job_id) in the format expected by lock events
    fn create_lock_key(job_id: u128) -> Vec<u8> {
        job_id.to_be_bytes().to_vec()
    }

    // ------------------------------------------------------------------------
    // Test: Deleting an existing revise rate request
    // Expected: Request should be deleted from the database
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_deleted_existing_request() -> Result<()> {
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
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(100)),
                revise_rate_requests::updates_at.eq(&revise_now),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;
        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000002"),
                revise_rate_requests::value.eq(BigDecimal::from(5)),
                revise_rate_requests::updates_at.eq(&creation_now.add(Duration::from_secs(600))),
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
                ),
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
                    BigDecimal::from(100),
                    revise_now,
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    BigDecimal::from(5),
                    creation_now.add(Duration::from_secs(600)),
                )
            ])
        );

        // Delete the lock
        let bcs_data =
            encode_lock_deleted_event(&[0u8; 4], &create_lock_key(1), rate_to_i_value(100));
        let log =
            TestSuiLog::new("LockDeleted", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
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
                ),
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
                creation_now.add(Duration::from_secs(600)),
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Deleting a nonexistent revise rate request
    // Expected: Should succeed silently (no error)
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_deleted_nonexistent_request() -> Result<()> {
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
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(100)),
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
                ),
            ])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(100),
                revise_now,
            ),])
        );

        let bcs_data =
            encode_lock_deleted_event(&[0u8; 4], &create_lock_key(3), rate_to_i_value(100));
        let log =
            TestSuiLog::new("LockDeleted", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
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
                ),
            ])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .order_by(revise_rate_requests::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(100),
                revise_now,
            ),])
        );

        Ok(())
    }
}
