use alloy::hex::ToHexExt;
use alloy::rpc::types::Log;
use anyhow::{Context, Result};
use diesel::{ExpressionMethods, PgConnection, RunQueryDsl};
use indexer_framework::schema::revise_rate_requests;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_revise_rate_cancelled(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = log.topics()[1].encode_hex_with_prefix();

    info!(id, "cancelling job rate revision");

    // target sql:
    // DELETE FROM revise_rate_requests
    // WHERE id = "<id>";
    let count = diesel::delete(revise_rate_requests::table)
        .filter(revise_rate_requests::id.eq(&id))
        .execute(conn)
        .context("failed to delete revise rate request")?;

    if count != 1 {
        // !!! should never happen
        // the only real condition is when the request does not exist or is already deleted
        // it is not a critical error, we can just move on
        warn!("did not expect to find a non existent request when cancelling job rate revision");
    }

    info!(id, "deleted revise rate request");

    Ok(())
}

// TODO: add tests
