use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use indexer_framework::schema::revise_rate_requests;
use indexer_framework::LogsProvider;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobClosed event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobClosedEvent {
    pub job_id: u128,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_closed(
    conn: &mut PgConnection,
    parsed: &ParsedSuiLog,
    provider: &impl LogsProvider,
) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobClosedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobClosed event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let block = parsed.checkpoint;

    // Fetch the block timestamp from the RPC,
    // can remove once alloy supports block_timestamp
    let block_timestamp = provider.block_timestamp(block)?;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, ?block, ?block_timestamp, "closing job");

    // target sql:
    // UPDATE jobs
    // SET is_closed = true, rate = 0, balance = 0, end_epoch = block_timestamp
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((
            jobs::is_closed.eq(true),
            jobs::rate.eq(BigDecimal::from(0)),
            jobs::balance.eq(BigDecimal::from(0)),
            jobs::end_epoch.eq(BigDecimal::from(block_timestamp)),
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
    // DELETE FROM revise_rate_requests
    // WHERE id = "<id>";
    let count = diesel::delete(revise_rate_requests::table)
        .filter(revise_rate_requests::id.eq(&id))
        .execute(conn)
        .context("failed to delete revise rate request")?;

    if count != 0 {
        info!(
            "Job had an outstanding revise rate request, deleted it for job id {}",
            id
        );

        // target sql:
        // INSERT INTO rate_revisions (job_id, value, block, timestamp)
        // VALUES ("<id>", "<rate>", "<block>", "<block_timestamp>");
        diesel::insert_into(rate_revisions::table)
            .values((
                rate_revisions::job_id.eq(&id),
                rate_revisions::value.eq(&BigDecimal::from(0)),
                rate_revisions::block.eq(block as i64),
                rate_revisions::timestamp.eq(BigDecimal::from(block_timestamp)),
            ))
            .execute(conn)
            .context("failed to insert rate revision")?;
    } else {
        info!("Job rate is already 0, no need to delete revise rate request");
    }

    info!(id, ?block, "closed job");

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
    use indexer_framework::schema::rate_revisions;
    use indexer_framework::schema::revise_rate_requests;

    // ------------------------------------------------------------------------
    // Test: Closing an existing job when the rate is not zero i.e. there is an outstanding revise rate request
    // Expected: Job should be closed, rate should be set to 0, balance should be set to 0, end_epoch should be set to the current timestamp
    // ------------------------------------------------------------------------
    #[test]
    fn test_close_existing_job_when_rate_is_not_zero() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata"),
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
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(BigDecimal::from(1)),
                jobs::balance.eq(BigDecimal::from(20)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (20))),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(0)),
                revise_rate_requests::updates_at.eq(&creation_now.add(Duration::from_secs(600))),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

        // Verify initial state
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "test-job-metadata".to_owned(),
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
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    BigDecimal::from(1),
                    BigDecimal::from(20),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (20)),
                ),
            ])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                creation_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_closed_event(1);
        let log =
            TestSuiLog::new("JobClosed", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(creation_timestamp);
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
                    "test-job-metadata".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(0),
                    BigDecimal::from(0),
                    original_now,
                    original_now,
                    true,
                    BigDecimal::from(original_timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    BigDecimal::from(1),
                    BigDecimal::from(20),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (20)),
                )
            ])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                1000,
                BigDecimal::from(original_timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET),
            )])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Closing an existing job when the rate is zero i.e. there is no outstanding revise rate request
    // Expected: Job should be closed, rate should be set to 0, balance should be set to 0, end_epoch should be set to the current timestamp
    // ------------------------------------------------------------------------
    #[test]
    fn test_close_existing_job_when_rate_is_zero() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata"),
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
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(BigDecimal::from(1)),
                jobs::balance.eq(BigDecimal::from(20)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(creation_timestamp + (20))),
            ))
            .execute(conn)
            .context("failed to create job")?;

        // if the rate is 0 then we must already have an entry for rate revision in the database
        diesel::insert_into(rate_revisions::table)
            .values((
                rate_revisions::job_id.eq("0x00000000000000000000000000000001"),
                rate_revisions::value.eq(BigDecimal::from(0)),
                rate_revisions::block.eq(42i64),
                rate_revisions::timestamp.eq(BigDecimal::from(original_timestamp)),
            ))
            .execute(conn)
            .context("failed to create rate revision")?;

        // Verify initial state
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x00000000000000000000000000000001".to_owned(),
                    "test-job-metadata".to_owned(),
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
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    BigDecimal::from(1),
                    BigDecimal::from(20),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (20)),
                ),
            ])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                42i64,
                BigDecimal::from(original_timestamp),
            )])
        );

        let bcs_data = encode_job_closed_event(1);
        let log =
            TestSuiLog::new("JobClosed", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(creation_timestamp);
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
                    "test-job-metadata".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(0),
                    BigDecimal::from(0),
                    original_now,
                    original_now,
                    true,
                    BigDecimal::from(original_timestamp + (DEFAULT_BLOCK_TIMESTAMP_OFFSET)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    BigDecimal::from(1),
                    BigDecimal::from(20),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (20)),
                )
            ])
        );

        // timestamp does not change since the rate revision entry was already in the database
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                42i64,
                BigDecimal::from(original_timestamp),
            )])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Closing a non-existent job
    // Expected: Error should be returned
    // ------------------------------------------------------------------------
    #[test]
    fn test_close_nonexistent_job() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(false),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp + (10000 / 100))),
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
                "test-job-metadata".to_owned(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            ),])
        );
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_closed_event(2);
        let log =
            TestSuiLog::new("JobClosed", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        let res = handle_log(conn, log, &provider);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "test-job-metadata".to_owned(),
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                BigDecimal::from(100),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            ),])
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Closing a closed job
    // Expected: Error should be returned but the job should remain closed
    // ------------------------------------------------------------------------
    #[test]
    fn test_close_already_closed_job() -> Result<()> {
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
                jobs::metadata.eq("test-job-metadata"),
                jobs::rate.eq(BigDecimal::from(0)),
                jobs::balance.eq(BigDecimal::from(0)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(true),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp)),
            ))
            .execute(conn)
            .context("failed to create job")?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "test-job-metadata".to_owned(),
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

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        // Try to close the already closed job
        let bcs_data = encode_job_closed_event(1);
        let log =
            TestSuiLog::new("JobClosed", "DigestABC123xyz789test", 1000, bcs_data).to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        let res = handle_log(conn, log, &provider);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");

        // Verify counts unchanged
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "test-job-metadata".to_owned(),
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

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
