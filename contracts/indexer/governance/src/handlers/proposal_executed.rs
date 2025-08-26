use alloy::hex::ToHexExt;
use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::{info, instrument};

use crate::schema::proposals;

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_proposal_executed(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing proposal executed");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    info!(?proposal_id, ?tx_hash, "executing proposal");

    // target sql:
    // UPDATE proposals
    // SET executed = true
    // WHERE id = "<proposal_id>"
    // AND executed = false
    let count = diesel::update(proposals::table)
        .filter(proposals::id.eq(&proposal_id))
        .filter(proposals::executed.eq(false))
        .set(proposals::executed.eq(true))
        .execute(conn)
        .context("failed to update proposal execution status")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find proposal"));
    }

    info!(?proposal_id, ?tx_hash, "proposal executed");

    Ok(())
}
