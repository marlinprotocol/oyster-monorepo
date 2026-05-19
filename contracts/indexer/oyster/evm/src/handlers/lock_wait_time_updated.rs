use std::str::FromStr;

use alloy::primitives::U256;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::lock_duration;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_lock_wait_time_updated(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let (prev_lock_time, updated_lock_time) =
        <(U256, U256)>::abi_decode_sequence(&log.data().data, true)?;
    let (prev_lock_time, updated_lock_time) = (
        BigDecimal::from_str(&prev_lock_time.to_string())?,
        BigDecimal::from_str(&updated_lock_time.to_string())?,
    );

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
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use bigdecimal::BigDecimal;
    use diesel::QueryDsl;
    use ethp::{event, keccak256};

    use crate::handlers::handle_log;
    use crate::handlers::test_utils::MockProvider;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_lock_wait_time_updated_when_old_duration_is_wrong() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(0))
        );

        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("LockWaitTimeUpdated(bytes32,uint256,uint256)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    (100, 200).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

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

    #[test]
    fn test_lock_wait_time_updated_when_old_duration_is_correct() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(lock_duration::table.count().get_result(conn), Ok(1));
        assert_eq!(
            lock_duration::table
                .select(lock_duration::duration)
                .first(conn),
            Ok(BigDecimal::from(0))
        );

        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("LockWaitTimeUpdated(bytes32,uint256,uint256)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    (0, 200).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

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
