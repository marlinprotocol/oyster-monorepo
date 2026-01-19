use anyhow::Context;
use anyhow::Result;
use diesel::query_dsl::methods::FilterDsl;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::providers;
use serde::Deserialize;
use sui_sdk_types::Address;
use tracing::{info, instrument};

use crate::provider::ParsedSuiLog;

/// Sui ProviderAdded event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct ProviderAddedEvent {
    pub provider: Address,
    pub cp: String,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_provider_added(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    // Decode the BCS-encoded event data
    let event: ProviderAddedEvent = bcs::from_bytes(parsed.bcs_contents)
        .context("Failed to BCS decode ProviderAdded event data")?;

    let provider = event.provider.to_string();
    let cp = event.cp;

    info!(
        provider,
        cp,
        checkpoint = parsed.checkpoint,
        tx_digest = parsed.tx_digest,
        "processing ProviderAdded event"
    );

    // Insert or update provider
    // - Insert if provider does not exist
    // - Update if provider exists but is_active is false
    // - Error if provider exists and is_active is true
    let count = diesel::insert_into(providers::table)
        .values((
            providers::id.eq(&provider),
            providers::cp.eq(&cp),
            providers::is_active.eq(true),
            providers::block.eq(parsed.checkpoint as i64),
            providers::tx_hash.eq(parsed.tx_digest),
        ))
        .on_conflict(providers::id)
        .do_update()
        .set((providers::is_active.eq(true), providers::cp.eq(&cp)))
        .filter(providers::is_active.eq(false))
        .execute(conn)
        .context("failed to add provider")?;

    if count != 1 {
        // We have failed to make any changes
        // The only real condition is when there is an existing active provider
        return Err(anyhow::anyhow!("did not expect to find existing provider"));
    }

    info!(provider, cp, "inserted provider");

    Ok(())
}
