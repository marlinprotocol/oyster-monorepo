use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Result;
use diesel::PgConnection;
use ethp::event;
use tracing::warn;
use tracing::{info, instrument};

mod job_opened;
use job_opened::handle_job_opened;

mod job_deposited;
use job_deposited::handle_job_deposited;

// job logs
static JOB_OPENED: [u8; 32] = event!("JobOpened(bytes32,string,address,address)");
static JOB_DEPOSITED: [u8; 32] = event!("JobDeposited(bytes32,address,address,uint256)");

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
pub fn handle_log_v2(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing v2 log");

    let log_type = log
        .topic0()
        .ok_or(anyhow!("log does not have topic0, should never happen"))?;

    if log_type == JOB_OPENED {
        handle_job_opened(conn, log)
    } else if log_type == JOB_DEPOSITED {
        handle_job_deposited(conn, log)
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
