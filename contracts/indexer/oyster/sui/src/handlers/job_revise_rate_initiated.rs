use crate::provider::ParsedSuiLog;
use anyhow::Result;
use diesel::PgConnection;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_initiated(_conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    info!(
        event_name = parsed.event_name,
        tx_digest = parsed.tx_digest,
        checkpoint = parsed.checkpoint,
        "processing"
    );

    // we do not have enough data here to handle this properly
    // primarily the timestamp at which the rate can be updated after the lock

    info!("empty impl, supposed to be handled by LockCreated");

    Ok(())
}
