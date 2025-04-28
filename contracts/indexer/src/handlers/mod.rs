use alloy::rpc::types::Log;
use anyhow::Result;
use diesel::PgConnection;
use tracing::{instrument, warn};

mod v1;
mod v2;

use crate::constants::get_contract_upgrade_block;

// Helper function that can be used across the codebase
fn is_v2_contract(block_number: u64) -> bool {
    match get_contract_upgrade_block() {
        Some(block) => block_number > block,
        None => false, // If no upgrade block is provided, we only handle v1
    }
}

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log) -> Result<()> {
    let block_number = log
        .block_number
        .ok_or_else(|| anyhow::anyhow!("Log missing block number"))?;

    if is_v2_contract(block_number) {
        v2::handle_log_v2(conn, log)
    } else {
        v1::handle_log_v1(conn, log)
    }
}

#[cfg(test)]
mod test_db;
