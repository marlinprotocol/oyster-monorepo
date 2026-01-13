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

// #[cfg(test)]
// mod tests {
//     use alloy::{primitives::LogData, rpc::types::Log};
//     use anyhow::Result;
//     use diesel::QueryDsl;
//     use ethp::{event, keccak256};

//     use crate::handlers::handle_log;
//     use crate::handlers::test_utils::MockProvider;
//     use crate::handlers::test_utils::TestDb;

//     use super::*;

//     #[test]
//     fn test_add_new_provider_in_empty_db() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         assert_eq!(providers::table.count().get_result(conn), Ok(0));

//         // log under test
//         let log = Log {
//             block_hash: Some(keccak256!("some block").into()),
//             block_number: Some(42),
//             block_timestamp: None,
//             log_index: Some(69),
//             transaction_hash: Some(keccak256!("some tx").into()),
//             transaction_index: Some(420),
//             removed: false,
//             inner: alloy::primitives::Log {
//                 address: contract,
//                 data: LogData::new(
//                     vec![
//                         event!("ProviderAdded(address,string)").into(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     "some cp".abi_encode().into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         // using timestamp 0 because we don't care about it
//         let provider = MockProvider::new(0);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(providers::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             providers::table.select(providers::all_columns).first(conn),
//             Ok((
//                 "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                 "some cp".to_owned(),
//                 42,
//                 (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
//                 true
//             ))
//         );

//         Ok(())
//     }

//     #[test]
//     fn test_add_new_provider_in_populated_db() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         diesel::insert_into(providers::table)
//             .values((
//                 providers::id.eq("0x7777777777777777777777777777777777777777"),
//                 providers::cp.eq("some other cp"),
//                 providers::block.eq(43i64),
//                 providers::tx_hash.eq(
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 ),
//                 providers::is_active.eq(true),
//             ))
//             .execute(conn)?;

//         assert_eq!(providers::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             providers::table.select(providers::all_columns).first(conn),
//             Ok((
//                 "0x7777777777777777777777777777777777777777".to_owned(),
//                 "some other cp".to_owned(),
//                 43,
//                 "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 true
//             ))
//         );

//         // log under test
//         let log = Log {
//             block_hash: Some(keccak256!("some block").into()),
//             block_number: Some(42),
//             block_timestamp: None,
//             log_index: Some(69),
//             transaction_hash: Some(keccak256!("some tx").into()),
//             transaction_index: Some(420),
//             removed: false,
//             inner: alloy::primitives::Log {
//                 address: contract,
//                 data: LogData::new(
//                     vec![
//                         event!("ProviderAdded(address,string)").into(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     "some cp".abi_encode().into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         // using timestamp 0 because we don't care about it
//         let provider = MockProvider::new(0);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(providers::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             providers::table
//                 .select(providers::all_columns)
//                 .order_by(providers::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x7777777777777777777777777777777777777777".to_owned(),
//                     "some other cp".to_owned(),
//                     43,
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 ),
//                 (
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     "some cp".to_owned(),
//                     42,
//                     (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
//                     true,
//                 )
//             ])
//         );

//         Ok(())
//     }

//     #[test]
//     fn test_add_new_provider_when_it_already_exists() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         diesel::insert_into(providers::table)
//             .values((
//                 providers::id.eq("0x7777777777777777777777777777777777777777"),
//                 providers::cp.eq("some other cp"),
//                 providers::block.eq(43i64),
//                 providers::tx_hash.eq(
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 ),
//                 providers::is_active.eq(true),
//             ))
//             .execute(conn)?;
//         diesel::insert_into(providers::table)
//             .values((
//                 providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
//                 providers::cp.eq("some cp"),
//                 providers::block.eq(42i64),
//                 providers::tx_hash.eq(
//                     "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 ),
//                 providers::is_active.eq(true),
//             ))
//             .execute(conn)?;

//         assert_eq!(providers::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             providers::table
//                 .select(providers::all_columns)
//                 .order_by(providers::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x7777777777777777777777777777777777777777".to_owned(),
//                     "some other cp".to_owned(),
//                     43,
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 ),
//                 (
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     "some cp".to_owned(),
//                     42,
//                     "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 )
//             ])
//         );

//         // log under test
//         let log = Log {
//             block_hash: Some(keccak256!("some block").into()),
//             block_number: Some(42),
//             block_timestamp: None,
//             log_index: Some(69),
//             transaction_hash: Some(keccak256!("some tx").into()),
//             transaction_index: Some(420),
//             removed: false,
//             inner: alloy::primitives::Log {
//                 address: contract,
//                 data: LogData::new(
//                     vec![
//                         event!("ProviderAdded(address,string)").into(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     "some cp".abi_encode().into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         // using timestamp 0 because we don't care about it
//         let provider = MockProvider::new(0);
//         // use handle_log instead of concrete handler to test dispatch
//         let res = handle_log(conn, log, &provider);

//         // checks
//         assert_eq!(
//             format!("{:?}", res.unwrap_err()),
//             "did not expect to find existing provider"
//         );
//         assert_eq!(providers::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             providers::table
//                 .select(providers::all_columns)
//                 .order_by(providers::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x7777777777777777777777777777777777777777".to_owned(),
//                     "some other cp".to_owned(),
//                     43,
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 ),
//                 (
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     "some cp".to_owned(),
//                     42,
//                     "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 )
//             ])
//         );

//         Ok(())
//     }

//     #[test]
//     fn test_add_new_provider_when_it_is_inactive() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         diesel::insert_into(providers::table)
//             .values((
//                 providers::id.eq("0x7777777777777777777777777777777777777777"),
//                 providers::cp.eq("some other cp"),
//                 providers::block.eq(43i64),
//                 providers::tx_hash.eq(
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 ),
//                 providers::is_active.eq(true),
//             ))
//             .execute(conn)?;
//         diesel::insert_into(providers::table)
//             .values((
//                 providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
//                 providers::cp.eq("some cp"),
//                 providers::block.eq(42i64),
//                 providers::tx_hash.eq(
//                     "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
//                 ),
//                 providers::is_active.eq(false),
//             ))
//             .execute(conn)?;

//         assert_eq!(providers::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             providers::table
//                 .select(providers::all_columns)
//                 .order_by(providers::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x7777777777777777777777777777777777777777".to_owned(),
//                     "some other cp".to_owned(),
//                     43,
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 ),
//                 (
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     "some cp".to_owned(),
//                     42,
//                     "0x999999999999999999999999999bcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     false,
//                 )
//             ])
//         );

//         // log under test
//         let log = Log {
//             block_hash: Some(keccak256!("some block").into()),
//             block_number: Some(42),
//             block_timestamp: None,
//             log_index: Some(69),
//             transaction_hash: Some(keccak256!("some tx").into()),
//             transaction_index: Some(420),
//             removed: false,
//             inner: alloy::primitives::Log {
//                 address: contract,
//                 data: LogData::new(
//                     vec![
//                         event!("ProviderAdded(address,string)").into(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     "some random cp".abi_encode().into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         // using timestamp 0 because we don't care about it
//         let provider = MockProvider::new(0);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(providers::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             providers::table
//                 .select(providers::all_columns)
//                 .order_by(providers::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x7777777777777777777777777777777777777777".to_owned(),
//                     "some other cp".to_owned(),
//                     43,
//                     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned(),
//                     true,
//                 ),
//                 (
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     "some random cp".to_owned(),
//                     42,
//                     (&keccak256!("some tx")).encode_hex_with_prefix().to_owned(),
//                     true,
//                 )
//             ])
//         );

//         Ok(())
//     }
// }
