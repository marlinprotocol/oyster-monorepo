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

#[cfg(test)]
mod tests {
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::*;
    use anyhow::Result;
    use diesel::ExpressionMethods;
    use diesel::QueryDsl;
    use diesel::RunQueryDsl;
    use indexer_framework::schema::providers;
    use sui_sdk_types::Address;

    // ------------------------------------------------------------------------
    // Test: Adding a new provider to an empty database
    // Expected: Provider should be inserted successfully with is_active = true
    // ------------------------------------------------------------------------
    #[test]
    fn test_new_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_provider_added_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            "https://test.provider.com/api",
        );
        let log = TestSuiLog::new("ProviderAdded", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider)?;

        // Verify provider was inserted
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test".to_owned(),
                true
            ))
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Adding a provider that already exists and is active
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_existing_active_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_provider_added_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            "https://test.provider.com/api",
        );
        let log = TestSuiLog::new("ProviderAdded", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        // First addition should succeed and fail since provider is already active
        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test".to_owned(),
                true
            ))
        );

        // Second addition should fail since provider is already active
        let bcs_data_2 = encode_provider_added_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            "https://new-cp.com",
        );
        let log_2 =
            TestSuiLog::new("ProviderAdded", "DigestXYZ456", 1000 + 1, bcs_data_2).to_alloy_log();

        let result = handle_log(conn, log_2, &provider);

        assert_eq!(
            result.unwrap_err().to_string(),
            "did not expect to find existing provider"
        );

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test".to_owned(),
                true
            ))
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Re-adding a provider that was previously removed (is_active = false)
    // Expected: Should succeed and update is_active to true, update cp
    // ------------------------------------------------------------------------
    #[test]
    fn test_existing_inactive_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        diesel::insert_into(providers::table)
            .values((
                providers::id
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                providers::cp.eq("https://test.provider.com/api"),
                providers::block.eq(1000i64),
                providers::tx_hash.eq("DigestABC123xyz789test".to_owned()),
                providers::is_active.eq(false),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test".to_owned(),
                false
            ))
        );

        // log under test
        let bcs_data = encode_provider_added_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
            "https://new-cp.com",
        );
        let log = TestSuiLog::new("ProviderAdded", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider).unwrap();

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://new-cp.com".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test".to_owned(),
                true
            ))
        );

        Ok(())
    }
}
