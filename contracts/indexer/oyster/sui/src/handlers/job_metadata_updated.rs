use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use serde::Deserialize;
use tracing::{info, instrument};

/// Sui JobMetadataUpdated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobMetadataUpdatedEvent {
    pub job_id: u128,
    pub new_metadata: String,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_metadata_updated(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobMetadataUpdatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobMetadataUpdated event data")?;

    // Convert job_id to hex string format
    let id = format!("0x{:032x}", event.job_id);
    let metadata = event.new_metadata;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, ?metadata, "updating job metadata");

    // target sql:
    // UPDATE jobs
    // SET metadata = "<metadata>"
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set(jobs::metadata.eq(&metadata))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    info!(id, ?metadata, "updated job metadata");

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

    // ------------------------------------------------------------------------
    // Test: Updating metadata for an existing active job
    // Expected: Job metadata should be updated, other fields preserved
    // ------------------------------------------------------------------------
    #[test]
    fn test_update_metadata_existing_job() -> Result<()> {
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
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "original-metadata-2".to_owned(),
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

        // Update the metadata
        let bcs_data = encode_job_metadata_updated_event(1, "updated-metadata-1");
        let log = TestSuiLog::new(
            "JobMetadataUpdated",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

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
                    "updated-metadata-1".to_owned(),
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    BigDecimal::from(100),
                    BigDecimal::from(10000),
                    creation_now,
                    creation_now,
                    false,
                    BigDecimal::from(creation_timestamp + (10000 / 100)),
                ),
                (
                    "0x00000000000000000000000000000002".to_owned(),
                    "original-metadata-2".to_owned(),
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

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Updating metadata for a nonexistent job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_update_metadata_nonexistent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        // Verify initial state
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_job_metadata_updated_event(999, "some-metadata");
        let log = TestSuiLog::new(
            "JobMetadataUpdated",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(0);
        let result = handle_log(conn, log, &provider);
        assert_eq!(format!("{:?}", result.unwrap_err()), "could not find job");

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Updating metadata for a closed job
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_update_metadata_closed_job() -> Result<()> {
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
                jobs::metadata.eq("original-metadata"),
                jobs::rate.eq(BigDecimal::from(100)),
                jobs::balance.eq(BigDecimal::from(10000)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(true),
                jobs::end_epoch.eq(BigDecimal::from(original_timestamp + (10000 / 100))),
            ))
            .execute(conn)
            .context("failed to create job")?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x00000000000000000000000000000001".to_owned(),
                "original-metadata".to_owned(),
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

        let bcs_data = encode_job_metadata_updated_event(1, "new-metadata");
        let log = TestSuiLog::new(
            "JobMetadataUpdated",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        let provider = MockProvider::new(original_timestamp);
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
                "original-metadata".to_owned(),
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

        Ok(())
    }
}
