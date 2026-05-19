use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use indexer_framework::schema::revise_rate_requests;
use indexer_framework::LogsProvider;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobReviseRateFinalized event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobReviseRateFinalizedEvent {
    pub job_id: u128,
    pub new_rate: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_finalized(
    conn: &mut PgConnection,
    parsed: &ParsedSuiLog,
    provider: &impl LogsProvider,
) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobReviseRateFinalizedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobReviseRateFinalized event data")?;

    // Convert to appropriate formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let rate = BigDecimal::from(event.new_rate);
    let block = parsed.checkpoint;

    // Fetch the block timestamp from the RPC,
    // can remove once alloy supports block_timestamp
    let block_timestamp = provider.block_timestamp(block)?;

    info!(
        id,
        ?rate,
        ?block,
        ?block_timestamp,
        "finalizing job rate revision"
    );

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    // get the reduced job balance as jobs get settled when the rate is revised
    let job_balance = jobs::table
        .filter(jobs::id.eq(&id))
        .filter(jobs::is_closed.eq(false))
        .select(jobs::balance)
        .get_result::<BigDecimal>(conn)
        .context("failed to get job balance");

    if job_balance.is_err() {
        // !!! should never happen
        // the only reason this would happen is if the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("failed to find balance for job"));
    }

    let job_balance = job_balance.unwrap();
    let mut new_end_epoch = BigDecimal::from(block_timestamp);

    // Calculate new end_epoch: timestamp + (balance / rate) (no scaling factor for Sui)
    if rate != BigDecimal::from(0) {
        new_end_epoch = new_end_epoch + (&job_balance / &rate).round(0);
    }

    info!(id, ?job_balance, ?new_end_epoch, "calculated new end epoch");

    // target sql:
    // UPDATE jobs
    // SET rate = <rate>, end_epoch = <new_end_epoch>
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set((jobs::rate.eq(&rate), jobs::end_epoch.eq(&new_end_epoch)))
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

    if count != 1 {
        // !!! should never happen
        // the only real condition is when the request does not exist
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!(
            "did not expect to find a non existent request when finalizing job rate revision"
        ));
    }

    // target sql:
    // INSERT INTO rate_revisions (job_id, value, block, timestamp)
    // VALUES ("<id>", "<rate>", "<block>", "<block_timestamp>");
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job_id.eq(&id),
            rate_revisions::value.eq(&rate),
            rate_revisions::block.eq(block as i64),
            rate_revisions::timestamp.eq(BigDecimal::from(block_timestamp)),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(id, ?rate, "finalized job rate revision");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use std::time::Duration;

    use crate::handlers::handle_log;
    use crate::handlers::test_utils::*;
    use bigdecimal::BigDecimal;
    use diesel::ExpressionMethods;
    use diesel::QueryDsl;
    use diesel::RunQueryDsl;
    use indexer_framework::schema::jobs;
    use indexer_framework::schema::rate_revisions;

    use super::*;

    // ------------------------------------------------------------------------
    // Test: Finalizing rate revision for an existing active job
    // Expected: Job rate and end_epoch should be updated, rate revision created
    // ------------------------------------------------------------------------
    #[test]
    fn test_revise_rate_finalized_existing_job() -> Result<()> {
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
                revise_rate_requests::value.eq(BigDecimal::from(200)),
                revise_rate_requests::updates_at.eq(&original_now.add(Duration::from_secs(600))),
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

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(200),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        // Finalize rate revision to new rate
        let new_rate: u64 = 200;
        let bcs_data = encode_job_revise_rate_finalized_event(1, new_rate);
        let log = TestSuiLog::new(
            "JobReviseRateFinalized",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
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
                    "test-job-metadata".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(200),
                    BigDecimal::from(10000),
                    original_now,
                    original_now,
                    false,
                    BigDecimal::from(
                        original_timestamp + (10000 / 200) + DEFAULT_BLOCK_TIMESTAMP_OFFSET
                    ),
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
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(200),
                1000 as i64,
                BigDecimal::from(original_timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET),
            ))
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Finalizing rate revision with zero rate
    // Expected: Rate should be set to 0, end_epoch should equal current timestamp
    // ------------------------------------------------------------------------
    #[test]
    fn test_revise_rate_finalized_zero_rate() -> Result<()> {
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

        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(0)),
                revise_rate_requests::updates_at.eq(&original_now.add(Duration::from_secs(600))),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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
        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        // Finalize rate revision to zero
        let bcs_data = encode_job_revise_rate_finalized_event(1, 0);
        let log = TestSuiLog::new(
            "JobReviseRateFinalized",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
        handle_log(conn, log, &provider)?;

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
                BigDecimal::from(0),
                BigDecimal::from(10000),
                original_now,
                original_now,
                false,
                BigDecimal::from(original_timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET),
            ),])
        );
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                1000 as i64,
                BigDecimal::from(original_timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET),
            ))
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Finalizing rate revision for a nonexistent job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_revise_rate_finalized_nonexistent_job() -> Result<()> {
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

        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(0)),
                revise_rate_requests::updates_at.eq(&original_now.add(Duration::from_secs(600))),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let job_id: u128 = 999;
        let new_rate: u64 = 200;

        let bcs_data = encode_job_revise_rate_finalized_event(job_id, new_rate);
        let log = TestSuiLog::new(
            "JobReviseRateFinalized",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
        let result = handle_log(conn, log, &provider);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to find balance for job"));

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
        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Finalizing rate revision for a closed job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_revise_rate_finalized_closed_job() -> Result<()> {
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
                jobs::is_closed.eq(true),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp + (10000 / 100))),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(revise_rate_requests::table)
            .values((
                revise_rate_requests::id.eq("0x00000000000000000000000000000001"),
                revise_rate_requests::value.eq(BigDecimal::from(0)),
                revise_rate_requests::updates_at.eq(&original_now.add(Duration::from_secs(600))),
            ))
            .execute(conn)
            .context("failed to create revise rate request")?;

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
                true,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            ),])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_revise_rate_finalized_event(1, 200);
        let log = TestSuiLog::new(
            "JobReviseRateFinalized",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
        let res = handle_log(conn, log, &provider);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to find balance for job"
        );

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
                true,
                BigDecimal::from(original_timestamp + (10000 / 100)),
            ),])
        );

        assert_eq!(revise_rate_requests::table.count().get_result(conn), Ok(1));
        assert_eq!(
            revise_rate_requests::table
                .select(revise_rate_requests::all_columns)
                .first(conn),
            Ok((
                "0x00000000000000000000000000000001".to_owned(),
                BigDecimal::from(0),
                original_now.add(Duration::from_secs(600)),
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
