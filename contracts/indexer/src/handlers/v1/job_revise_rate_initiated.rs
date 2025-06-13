use alloy::rpc::types::Log;
use anyhow::Result;
use diesel::PgConnection;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_revise_rate_initiated(_conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    // we do not have enough data here to handle this properly
    // primarily the timestamp at which the rate can be updated after the lock

    info!("empty impl, supposed to be handled by LockCreated");

    Ok(())
}
