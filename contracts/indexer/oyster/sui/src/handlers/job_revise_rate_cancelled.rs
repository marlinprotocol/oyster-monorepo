use crate::provider::ParsedSuiLog;
use anyhow::Result;
use diesel::PgConnection;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_revise_rate_cancelled(_conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    info!(
        event_name = parsed.event_name,
        tx_digest = parsed.tx_digest,
        checkpoint = parsed.checkpoint,
        "processing"
    );

    // while we do have enough context here to handle this properly,
    // JobClosed makes us handle LockDeleted
    // which also more or less handles this

    info!("empty impl, supposed to be handled by LockDeleted");

    Ok(())
}
