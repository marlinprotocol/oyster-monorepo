use indexer_framework::schema::providers;
use alloy::hex::ToHexExt;
use alloy::primitives::Address;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use diesel::QueryDsl;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_provider_added(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let provider = Address::from_word(log.topics()[1]).to_checksum(None);
    let cp = String::abi_decode(&log.data().data, true)?;

    let block = log
        .block_number
        .ok_or(anyhow!("did not get block from log"))?;
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    // we want to insert if provider does not exist
    // we want to update if provider exists
    // an existing active provider is not expected since the contract does not
    // allow adding a provider twice, the row is replaced with what the chain says

    info!(provider, cp, ?block, ?tx_hash, "inserting provider");

    // target sql:
    // INSERT INTO providers (id, cp, is_active)
    // VALUES("<provider>", "<cp>", true)
    // ON CONFLICT (id)
    // DO UPDATE SET
    //     is_active = true
    //     cp = "<cp>";
    let existing_active = providers::table
        .filter(providers::id.eq(&provider))
        .filter(providers::is_active.eq(true))
        .count()
        .get_result::<i64>(conn)
        .context("failed to check for existing provider")?;
    if existing_active != 0 {
        warn!(provider, ?block, "provider already exists, replacing it");
    }

    diesel::insert_into(providers::table)
        .values((
            providers::id.eq(&provider),
            providers::cp.eq(&cp),
            providers::is_active.eq(true),
            providers::block.eq(block as i64),
            providers::tx_hash.eq(&tx_hash),
        ))
        .on_conflict(providers::id)
        .do_update()
        .set((
            providers::is_active.eq(true),
            providers::cp.eq(&cp),
            providers::block.eq(block as i64),
            providers::tx_hash.eq(&tx_hash),
        ))
        .execute(conn)
        .context("failed to add provider")?;

    info!(provider, cp, "inserted provider");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::{event, keccak256};

    use crate::handlers::handle_log;
    use crate::handlers::test_utils::MockProvider;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_add_new_provider_in_empty_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                42,
                (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
                true
            ))
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_in_populated_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::block.eq(43i64),
                providers::tx_hash.eq(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                ),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x7777777777777777777777777777777777777777".to_owned(),
                "some other cp".to_owned(),
                43,
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                true
            ))
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    43,
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    42,
                    (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_when_it_already_exists() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::block.eq(43i64),
                providers::tx_hash.eq(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                ),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;
        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::block.eq(42i64),
                providers::tx_hash.eq(
                    "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
                ),
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
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    43,
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    42,
                    "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                )
            ])
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "new cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        // checks
        // the existing row is replaced with the data from the event
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    43,
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "new cp".to_owned(),
                    42,
                    keccak256!("some tx").encode_hex_with_prefix(),
                    true,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_when_it_is_inactive() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::block.eq(43i64),
                providers::tx_hash.eq(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                ),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;
        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::block.eq(42i64),
                providers::tx_hash.eq(
                    "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
                ),
                providers::is_active.eq(false),
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
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    43,
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    42,
                    "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
                    false,
                )
            ])
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some random cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // using timestamp 0 because we don't care about it
        let provider = MockProvider::new(0);
        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log, &provider)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    43,
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some random cp".to_owned(),
                    42,
                    (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }
}
