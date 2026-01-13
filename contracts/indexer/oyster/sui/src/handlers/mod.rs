use alloy::rpc::types::Log;
use anyhow::{anyhow, Result};
use diesel::PgConnection;
use indexer_framework::LogsProvider;
use tracing::{debug, info, instrument, warn};

use crate::provider::parse_sui_log;

mod provider_added;
use provider_added::handle_provider_added;

mod provider_removed;
use provider_removed::handle_provider_removed;

mod provider_updated_with_cp;
use provider_updated_with_cp::handle_provider_updated_with_cp;

mod job_opened;
use job_opened::handle_job_opened;

mod job_withdrew;
use job_withdrew::handle_job_withdrew;

mod job_revise_rate_initiated;
use job_revise_rate_initiated::handle_job_revise_rate_initiated;

mod job_revise_rate_cancelled;
use job_revise_rate_cancelled::handle_job_revise_rate_cancelled;

mod job_metadata_updated;
use job_metadata_updated::handle_job_metadata_updated;
#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log, _provider: &impl LogsProvider) -> Result<()> {
    // Debug: log raw data length
    let raw_data = log.data().data.as_ref();
    debug!(
        raw_data_len = raw_data.len(),
        raw_data_hex = hex::encode(raw_data),
        "Raw log data"
    );

    // Parse the Sui log to extract event name, tx_digest, checkpoint and BCS contents
    let parsed = parse_sui_log(&log).ok_or_else(|| anyhow!("Failed to parse Sui log data"))?;

    info!(
        event_name = parsed.event_name,
        tx_digest = parsed.tx_digest,
        checkpoint = parsed.checkpoint,
        bcs_len = parsed.bcs_contents.len(),
        "processing Sui event"
    );

    // Match on event name directly
    match parsed.event_name {
        "ProviderAdded" => handle_provider_added(conn, &parsed),
        "ProviderRemoved" => handle_provider_removed(conn, &parsed),
        "ProviderUpdatedWithCp" => handle_provider_updated_with_cp(conn, &parsed),
        "JobOpened" => handle_job_opened(conn, &parsed),
        "JobWithdrew" => handle_job_withdrew(conn, &parsed),
        "JobReviseRateInitiated" => handle_job_revise_rate_initiated(conn, &parsed),
        "JobReviseRateCancelled" => handle_job_revise_rate_cancelled(conn, &parsed),
        "JobMetadataUpdated" => handle_job_metadata_updated(conn, &parsed),
        // Ignored events
        "Upgraded" | "LockWaitTimeUpdated" | "RoleGranted" | "TokenUpdated" | "Initialized" => {
            info!(event_name = parsed.event_name, "ignoring event type");
            Ok(())
        }
        _ => {
            warn!(event_name = parsed.event_name, "unknown event type");
            Ok(())
        }
    }
}

