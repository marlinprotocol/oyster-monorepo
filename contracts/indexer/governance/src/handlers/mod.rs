use alloy::rpc::types::Log;
use anyhow::Result;
use diesel::PgConnection;
use tracing::warn;
use tracing::{info, instrument};

mod governance_contract;
use governance_contract::handle_governance_contract_log;

mod market_contract;
use market_contract::handle_market_contract_log;

use crate::constants::{get_governance_contract, get_market_contract};

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing log");

    let log_contract = log.address();

    if log_contract == get_governance_contract() {
        handle_governance_contract_log(conn, log)
    } else if log_contract == get_market_contract() {
        handle_market_contract_log(conn, log)
    } else {
        warn!(?log_contract, "unknown contract");
        Ok(())
    }
}

#[cfg(test)]
mod test_db;
