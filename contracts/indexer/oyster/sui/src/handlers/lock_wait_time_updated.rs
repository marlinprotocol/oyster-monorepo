use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::lock_duration;
use serde::Deserialize;
use tracing::{info, instrument};

use crate::provider::ParsedSuiLog;

/// Sui LockWaitTimeUpdated event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LockWaitTimeUpdatedEvent {
    pub selector: Vec<u8>,
    pub prev_lock_time: u64,
    pub updated_lock_time: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_lock_wait_time_updated(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    let event: LockWaitTimeUpdatedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode LockWaitTimeUpdated event data")?;

    let prev_lock_time = BigDecimal::from(event.prev_lock_time);
    let updated_lock_time = BigDecimal::from(event.updated_lock_time);

    info!(
        ?prev_lock_time,
        ?updated_lock_time,
        "updating lock wait time"
    );

    // target sql:
    // UPDATE lock_duration
    // SET duration = "<updated_lock_time>"
    // WHERE duration = "<prev_lock_time>";
    let count = diesel::update(lock_duration::table)
        .filter(lock_duration::duration.eq(&prev_lock_time))
        .set(lock_duration::duration.eq(&updated_lock_time))
        .execute(conn)
        .context("failed to update lock wait time")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the lock wait time does not match the previous lock wait time
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not update lock wait time"));
    }

    info!(
        ?prev_lock_time,
        ?updated_lock_time,
        "updated lock wait time"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::*;
    use anyhow::Result;
    use bigdecimal::BigDecimal;
    use diesel::QueryDsl;
    use diesel::RunQueryDsl;
    use indexer_framework::schema::lock_duration;

    // ------------------------------------------------------------------------
    // Test: Updating lock wait time when the old duration does not match
    // Expected: Error should be returned, lock duration should remain unchanged
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_wait_time_updated_when_old_duration_is_wrong() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(0))
        );

        let bcs_data = encode_lock_wait_time_updated_event(vec![0], 100, 200);
        let log = TestSuiLog::new(
            "LockWaitTimeUpdated",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);

        let res = handle_log(conn, log, &provider);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "could not update lock wait time"
        );

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(0))
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Updating lock wait time when the old duration matches
    // Expected: Lock duration should be updated to the new value
    // ------------------------------------------------------------------------
    #[test]
    fn test_lock_wait_time_updated_when_old_duration_is_correct() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(0))
        );

        let bcs_data = encode_lock_wait_time_updated_event(vec![0], 0, 200);
        let log = TestSuiLog::new(
            "LockWaitTimeUpdated",
            "DigestABC123xyz789test",
            1000,
            bcs_data,
        )
        .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);

        handle_log(conn, log, &provider)?;

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(200))
        );

        Ok(())
    }
}
