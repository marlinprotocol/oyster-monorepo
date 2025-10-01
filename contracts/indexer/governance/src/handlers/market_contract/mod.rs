use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Result;
use diesel::PgConnection;
use ethp::event;
use tracing::warn;
use tracing::{info, instrument};

mod job_opened;
use job_opened::handle_job_opened;

static JOB_OPENED: [u8; 32] =
    event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)");
static UPGRADED: [u8; 32] = event!("Upgraded(address)");

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_market_contract_log(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing market contract log");

    let log_type = log
        .topic0()
        .ok_or(anyhow!("log does not have topic0, should never happen"))?;

    if log_type == JOB_OPENED {
        handle_job_opened(conn, log)
    } else if log_type == UPGRADED {
        info!(?log_type, "ignoring log type");
        Ok(())
    } else {
        warn!(?log_type, "unknown log type");
        Ok(())
    }
}
