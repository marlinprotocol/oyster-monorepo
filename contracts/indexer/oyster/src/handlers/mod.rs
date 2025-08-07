use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Result;
use diesel::PgConnection;
use ethp::event;
use tracing::warn;
use tracing::{info, instrument};

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

mod lock_created;
use lock_created::handle_lock_created;

mod lock_deleted;
use lock_deleted::handle_lock_deleted;

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

// we need the unlock time for JobReviseRateInitiated, use LockCreated directly instead
// blergh
static LOCK_CREATED: [u8; 32] = event!("LockCreated(bytes32,bytes32,uint256,uint256)");

// need to set revise rate requests to completed on both JobReviseRateFinalized and JobClosed
// but not if JobClosed is emitted after a rate change is already finalized
// or job is closed when rate is zero without any rate changes
// way simpler to just use the lock event
// blergh
static LOCK_DELETED: [u8; 32] = event!("LockDeleted(bytes32,bytes32,uint256)");

// ignored logs
static UPGRADED: [u8; 32] = event!("Upgraded(address)");
static LOCK_WAIT_TIME_UPDATED: [u8; 32] = event!("LockWaitTimeUpdated(bytes32,uint256,uint256)");
static ROLE_GRANTED: [u8; 32] = event!("RoleGranted(bytes32,address,address)");
static TOKEN_UPDATED: [u8; 32] = event!("TokenUpdated(address,address)");
static INITIALIZED: [u8; 32] = event!("Initialized(uint8)");

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log) -> Result<()> {
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
        handle_job_closed(conn, log)
    } else if log_type == JOB_DEPOSITED {
        handle_job_deposited(conn, log)
    } else if log_type == JOB_WITHDREW {
        handle_job_withdrew(conn, log)
    } else if log_type == JOB_REVISE_RATE_INITIATED {
        handle_job_revise_rate_initiated(conn, log)
    } else if log_type == JOB_REVISE_RATE_CANCELLED {
        handle_job_revise_rate_cancelled(conn, log)
    } else if log_type == JOB_REVISE_RATE_FINALIZED {
        handle_job_revise_rate_finalized(conn, log)
    } else if log_type == JOB_METADATA_UPDATED {
        handle_job_metadata_updated(conn, log)
    } else if log_type == LOCK_CREATED {
        handle_lock_created(conn, log)
    } else if log_type == LOCK_DELETED {
        handle_lock_deleted(conn, log)
    } else if log_type == UPGRADED
        || log_type == LOCK_WAIT_TIME_UPDATED
        || log_type == ROLE_GRANTED
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
mod test_db;
