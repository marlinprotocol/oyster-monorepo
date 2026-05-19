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
    // Test: Removing an existing active provider
    // Expected: Provider's is_active should be set to false
    // ------------------------------------------------------------------------
    #[test]
    fn test_remove_existing_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        diesel::insert_into(providers::table)
            .values((
                providers::id
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                providers::cp.eq("https://test.provider.com/api1"),
                providers::block.eq(1000i64),
                providers::tx_hash.eq("DigestABC123xyz789test1".to_owned()),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;
        diesel::insert_into(providers::table)
            .values((
                providers::id
                    .eq("0x0202020202020202020202020202020202020202020202020202020202020202"),
                providers::cp.eq("https://test.provider.com/api2"),
                providers::block.eq(1001i64),
                providers::tx_hash.eq("DigestABC123xyz789test2".to_owned()),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "https://test.provider.com/api1".to_owned(),
                    1000 as i64,
                    "DigestABC123xyz789test1".to_owned(),
                    true,
                ),
                (
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    "https://test.provider.com/api2".to_owned(),
                    1001 as i64,
                    "DigestABC123xyz789test2".to_owned(),
                    true,
                )
            ])
        );

        // Now remove the provider
        let bcs_data = encode_provider_removed_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
        );
        let log = TestSuiLog::new(
            "ProviderRemoved",
            "DigestABC123xyz789test",
            1000 + 1,
            bcs_data,
        )
        .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        handle_log(conn, log, &provider).unwrap();

        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                    "https://test.provider.com/api1".to_owned(),
                    1000 as i64,
                    "DigestABC123xyz789test1".to_owned(),
                    false,
                ),
                (
                    "0x0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
                    "https://test.provider.com/api2".to_owned(),
                    1001 as i64,
                    "DigestABC123xyz789test2".to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Removing a provider that does not exist
    // Expected: Should fail with an error
    // ------------------------------------------------------------------------
    #[test]
    fn test_remove_nonexistent_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        // Verify initial state
        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        let bcs_data = encode_provider_removed_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
        );
        let log = TestSuiLog::new("ProviderRemoved", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        let res = handle_log(conn, log, &provider);

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(0));
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "count 0 should have been 1"
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Test: Removing a provider that is already inactive
    // Expected: Should fail with an error (count will be 0)
    // ------------------------------------------------------------------------
    #[test]
    fn test_remove_inactive_provider() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        // Insert an inactive provider
        diesel::insert_into(providers::table)
            .values((
                providers::id
                    .eq("0x0101010101010101010101010101010101010101010101010101010101010101"),
                providers::cp.eq("https://test.provider.com/api1"),
                providers::block.eq(1000i64),
                providers::tx_hash.eq("DigestABC123xyz789test1".to_owned()),
                providers::is_active.eq(false),
            ))
            .execute(conn)?;

        // Verify initial state
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![(
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api1".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test1".to_owned(),
                false,
            )])
        );

        // Try to remove the already inactive provider
        let bcs_data = encode_provider_removed_event(
            &"0x0101010101010101010101010101010101010101010101010101010101010101"
                .parse::<Address>()?,
        );
        let log = TestSuiLog::new("ProviderRemoved", "DigestABC123xyz789test", 1000, bcs_data)
            .to_alloy_log();

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        let result = handle_log(conn, log, &provider);
        assert!(result.is_err());
        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            "count 0 should have been 1"
        );

        // Verify count unchanged
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![(
                "0x0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
                "https://test.provider.com/api1".to_owned(),
                1000 as i64,
                "DigestABC123xyz789test1".to_owned(),
                false,
            )])
        );

        Ok(())
    }
}
