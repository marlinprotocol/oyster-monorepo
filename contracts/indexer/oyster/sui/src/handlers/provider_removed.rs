use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::providers;
use serde::Deserialize;
use sui_sdk_types::Address;
use tracing::{info, instrument};

use crate::provider::ParsedSuiLog;

/// Sui ProviderRemoved event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct ProviderRemovedEvent {
    pub provider: Address,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_provider_removed(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    // Decode the BCS-encoded event data
    let event: ProviderRemovedEvent = bcs::from_bytes(parsed.bcs_contents)
        .context("Failed to BCS decode ProviderRemoved event data")?;

    let provider = event.provider.to_string();

    // we want to deactivate if provider is active
    // we want to error out if provider is not active

    info!(provider, "removing provider");

    // target sql:
    // UPDATE providers
    // SET is_active = false
    // WHERE id = "<id>"
    // AND is_active = true;
    let count = diesel::update(providers::table)
        .filter(providers::id.eq(&provider))
        // we want to detect if provider is already inactive
        // we do it by only updating rows where is_active is true
        // and later checking if any rows were updated
        .filter(providers::is_active.eq(true))
        .set(providers::is_active.eq(false))
        .execute(conn)
        .context("failed to remove provider")?;

    if count != 1 {
        // !!! should never happen
        // we should have had exactly one row made inactive
        // if count is 0, that means the row was already inactive
        // if count is more than 1, there was somehow more than one provider entry
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("count {count} should have been 1"));
    }

    info!(provider, "removed provider");

    Ok(())
}
