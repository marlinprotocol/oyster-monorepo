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

mod job_deposited;
use job_deposited::handle_job_deposited;

mod job_rate_revised;
use job_rate_revised::handle_job_rate_revised;

mod job_settled;
use job_settled::handle_job_settled;

mod job_settlement_withdraw;
use job_settlement_withdraw::handle_job_settlement_withdraw;

mod job_withdrew;
use job_withdrew::handle_job_withdrew;

mod job_metadata_updated;
use job_metadata_updated::handle_job_metadata_updated;

mod job_closed;
use job_closed::handle_job_closed;

// job logs
static JOB_OPENED: [u8; 32] = event!("JobOpened(bytes32,string,address,address)");
static JOB_DEPOSITED: [u8; 32] = event!("JobDeposited(bytes32,address,address,uint256)");
static JOB_RATE_REVISED: [u8; 32] = event!("JobRateRevised(bytes32,uint256)");
static JOB_SETTLED: [u8; 32] = event!("JobSettled(bytes32,uint256)");
static JOB_SETTLED_WITHDRAW: [u8; 32] =
    event!("JobSettlementWithdrawn(bytes32,address,address,uint256)");
static JOB_WITHDRAWN: [u8; 32] = event!("JobWithdrawn(bytes32,address,address,uint256)");
static JOB_METADATA_UPDATED: [u8; 32] = event!("JobMetadataUpdated(bytes32,string)");
static JOB_CLOSED: [u8; 32] = event!("JobClosed(bytes32)");

// provider logs
static PROVIDER_ADDED: [u8; 32] = event!("ProviderAdded(address,string)");
static PROVIDER_REMOVED: [u8; 32] = event!("ProviderRemoved(address)");
static PROVIDER_UPDATED_WITH_CP: [u8; 32] = event!("ProviderUpdatedWithCp(address,string)");

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
    } else if log_type == JOB_RATE_REVISED {
        handle_job_rate_revised(conn, log)
    } else if log_type == JOB_SETTLED {
        handle_job_settled(conn, log)
    } else if log_type == JOB_SETTLED_WITHDRAW {
        handle_job_settlement_withdraw(conn, log)
    } else if log_type == JOB_WITHDRAWN {
        handle_job_withdrew(conn, log)
    } else if log_type == JOB_METADATA_UPDATED {
        handle_job_metadata_updated(conn, log)
    } else if log_type == JOB_CLOSED {
        handle_job_closed(conn, log)
    } else if log_type == PROVIDER_ADDED {
        handle_provider_added(conn, log)
    } else if log_type == PROVIDER_REMOVED {
        handle_provider_removed(conn, log)
    } else if log_type == PROVIDER_UPDATED_WITH_CP {
        handle_provider_updated_with_cp(conn, log)
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
