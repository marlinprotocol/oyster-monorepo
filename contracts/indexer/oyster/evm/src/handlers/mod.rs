use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Result;
use diesel::Connection;
use diesel::PgConnection;
use ethp::event;
use tracing::error;
use tracing::warn;
use tracing::{info, instrument};

use indexer_framework::LogsProvider;

mod provider_added;
use provider_added::handle_provider_added;

mod provider_removed;
use provider_removed::handle_provider_removed;

mod provider_updated_with_cp;
use provider_updated_with_cp::handle_provider_updated_with_cp;

mod job_opened;
use job_opened::handle_job_opened;

mod job_settled;
use job_settled::handle_job_settled;

mod job_closed;
use job_closed::handle_job_closed;

mod job_deposited;
use job_deposited::handle_job_deposited;

mod job_withdrew;
use job_withdrew::handle_job_withdrew;

mod job_revise_rate_initiated;
use job_revise_rate_initiated::handle_job_revise_rate_initiated;

mod job_revise_rate_cancelled;
use job_revise_rate_cancelled::handle_job_revise_rate_cancelled;

mod job_revise_rate_finalized;
use job_revise_rate_finalized::handle_job_revise_rate_finalized;

mod job_metadata_updated;
use job_metadata_updated::handle_job_metadata_updated;

mod lock_wait_time_updated;
use lock_wait_time_updated::handle_lock_wait_time_updated;

// provider logs
static PROVIDER_ADDED: [u8; 32] = event!("ProviderAdded(address,string)");
static PROVIDER_REMOVED: [u8; 32] = event!("ProviderRemoved(address)");
static PROVIDER_UPDATED_WITH_CP: [u8; 32] = event!("ProviderUpdatedWithCp(address,string)");

// job logs
static JOB_OPENED: [u8; 32] =
    event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)");
static JOB_SETTLED: [u8; 32] = event!("JobSettled(bytes32,uint256,uint256)");
static JOB_CLOSED: [u8; 32] = event!("JobClosed(bytes32)");
static JOB_DEPOSITED: [u8; 32] = event!("JobDeposited(bytes32,address,uint256)");
static JOB_WITHDREW: [u8; 32] = event!("JobWithdrew(bytes32,address,uint256)");
static JOB_REVISE_RATE_INITIATED: [u8; 32] = event!("JobReviseRateInitiated(bytes32,uint256)");
static JOB_REVISE_RATE_CANCELLED: [u8; 32] = event!("JobReviseRateCancelled(bytes32)");
static JOB_REVISE_RATE_FINALIZED: [u8; 32] = event!("JobReviseRateFinalized(bytes32,uint256)");
static JOB_METADATA_UPDATED: [u8; 32] = event!("JobMetadataUpdated(bytes32,string)");

// lock related events
static LOCK_WAIT_TIME_UPDATED: [u8; 32] = event!("LockWaitTimeUpdated(bytes32,uint256,uint256)");

// ignored logs
static UPGRADED: [u8; 32] = event!("Upgraded(address)");
static ROLE_GRANTED: [u8; 32] = event!("RoleGranted(bytes32,address,address)");
static LOCK_CREATED: [u8; 32] = event!("LockCreated(bytes32,bytes32,uint256,uint256)");
static LOCK_DELETED: [u8; 32] = event!("LockDeleted(bytes32,bytes32,uint256)");
static TOKEN_UPDATED: [u8; 32] = event!("TokenUpdated(address,address)");
static INITIALIZED: [u8; 32] = event!("Initialized(uint8)");

// Error returned by handlers when the row an event applies to is missing or is not
// in the state the event needs, e.g. the job does not exist or is already closed.
// The indexer never produces this by itself, it means the tables were changed from outside.
#[derive(Debug)]
pub struct StateMismatch(String);

impl std::fmt::Display for StateMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StateMismatch {}

fn state_mismatch(msg: impl Into<String>) -> anyhow::Error {
    StateMismatch(msg.into()).into()
}

// Entry point for the event loop.
// Logs which cannot be applied because of a state mismatch are logged and skipped,
// stopping on them would stop the indexer for good since every retry hits the same log.
// Any other error is returned, the event loop adds the block and log index to it.
pub fn process_log(conn: &mut PgConnection, log: Log, provider: &impl LogsProvider) -> Result<()> {
    let block = log.block_number;
    let idx = log.log_index;
    let tx = log.transaction_hash;

    // runs as a savepoint inside the range transaction
    // a handler that fails midway leaves nothing behind
    let res = conn.transaction(|conn| handle_log(conn, log, provider));

    match res {
        Err(err) if err.downcast_ref::<StateMismatch>().is_some() => {
            error!(
                ?block,
                ?idx,
                ?tx,
                ?err,
                "skipping log, the indexed state does not match the event"
            );
            Ok(())
        }
        res => res,
    }
}

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log, provider: &impl LogsProvider) -> Result<()> {
    info!(?log, "processing");

    let log_type = log
        .topic0()
        .ok_or(anyhow!("log does not have topic0, should never happen"))?;

    if log_type == PROVIDER_ADDED {
        handle_provider_added(conn, log)
    } else if log_type == PROVIDER_REMOVED {
        handle_provider_removed(conn, log)
    } else if log_type == PROVIDER_UPDATED_WITH_CP {
        handle_provider_updated_with_cp(conn, log)
    } else if log_type == JOB_OPENED {
        handle_job_opened(conn, log)
    } else if log_type == JOB_SETTLED {
        handle_job_settled(conn, log)
    } else if log_type == JOB_CLOSED {
        handle_job_closed(conn, log, provider)
    } else if log_type == JOB_DEPOSITED {
        handle_job_deposited(conn, log)
    } else if log_type == JOB_WITHDREW {
        handle_job_withdrew(conn, log)
    } else if log_type == JOB_REVISE_RATE_INITIATED {
        handle_job_revise_rate_initiated(conn, log, provider)
    } else if log_type == JOB_REVISE_RATE_CANCELLED {
        handle_job_revise_rate_cancelled(conn, log)
    } else if log_type == JOB_REVISE_RATE_FINALIZED {
        handle_job_revise_rate_finalized(conn, log, provider)
    } else if log_type == JOB_METADATA_UPDATED {
        handle_job_metadata_updated(conn, log)
    } else if log_type == LOCK_WAIT_TIME_UPDATED {
        handle_lock_wait_time_updated(conn, log)
    } else if log_type == UPGRADED
        || log_type == ROLE_GRANTED
        || log_type == LOCK_CREATED
        || log_type == LOCK_DELETED
        || log_type == TOKEN_UPDATED
        || log_type == INITIALIZED
    {
        info!(?log_type, "ignoring log type");
        Ok(())
    } else {
        warn!(?log_type, "unknown log type");
        Ok(())
    }
}

#[cfg(test)]
mod test_utils {
    mod test_db;
    mod test_provider;

    pub use test_db::TestDb;
    pub use test_provider::MockProvider;
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, LogData};
    use alloy::sol_types::SolValue;
    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use ethp::keccak256;
    use indexer_framework::schema::{jobs, providers, sync};

    use super::test_utils::{MockProvider, TestDb};
    use super::*;

    fn job_log(topic0: [u8; 32], job: &str, data: Vec<u8>) -> Result<Log> {
        Ok(Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: "0x1111111111111111111111111111111111111111".parse()?,
                data: LogData::new(vec![topic0.into(), job.parse()?], data.into()).unwrap(),
            },
        })
    }

    // events for jobs which are missing from the db do not stop the indexer
    #[test]
    fn test_process_log_skips_events_for_missing_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;
        let provider = MockProvider::new(0);
        let job = "0x3333333333333333333333333333333333333333333333333333333333333333";

        let logs = [
            job_log(JOB_CLOSED, job, vec![])?,
            job_log(JOB_SETTLED, job, (5, 6).abi_encode_sequence())?,
            job_log(JOB_DEPOSITED, job, 5.abi_encode())?,
            job_log(JOB_WITHDREW, job, 5.abi_encode())?,
            job_log(JOB_METADATA_UPDATED, job, "some metadata".abi_encode())?,
            job_log(JOB_REVISE_RATE_FINALIZED, job, 5.abi_encode())?,
        ];

        for log in logs {
            // the handler by itself reports the mismatch
            let err = handle_log(conn, log.clone(), &provider).unwrap_err();
            assert!(err.downcast_ref::<StateMismatch>().is_some(), "{err:?}");

            // the event loop entry point skips the log
            process_log(conn, log, &provider)?;
        }

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    #[test]
    fn test_process_log_skips_events_for_missing_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;
        let provider = MockProvider::new(0);
        let operator = "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
            .parse::<Address>()?
            .into_word()
            .to_string();

        process_log(conn, job_log(PROVIDER_REMOVED, &operator, vec![])?, &provider)?;
        process_log(
            conn,
            job_log(PROVIDER_UPDATED_WITH_CP, &operator, "some cp".abi_encode())?,
            &provider,
        )?;

        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    // a skipped log must not leave partial writes, and must not break the
    // range transaction it is processed in
    #[test]
    fn test_process_log_skip_inside_range_transaction() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;
        let provider = MockProvider::new(0);
        let job = "0x3333333333333333333333333333333333333333333333333333333333333333";

        conn.transaction(|conn| {
            process_log(conn, job_log(JOB_CLOSED, job, vec![])?, &provider)?;
            // later writes in the same transaction still go through
            diesel::update(sync::table)
                .set(sync::block.eq(42))
                .execute(conn)?;
            anyhow::Ok(())
        })?;

        assert_eq!(sync::table.select(sync::block).first(conn), Ok(42i64));

        Ok(())
    }

    // errors other than state mismatches are returned
    #[test]
    fn test_process_log_returns_other_errors() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;
        let provider = MockProvider::new(0);
        let job = "0x3333333333333333333333333333333333333333333333333333333333333333";

        // data cannot be decoded as a uint256
        let res = process_log(conn, job_log(JOB_DEPOSITED, job, vec![1, 2, 3])?, &provider);
        assert!(res.is_err());

        Ok(())
    }
}
