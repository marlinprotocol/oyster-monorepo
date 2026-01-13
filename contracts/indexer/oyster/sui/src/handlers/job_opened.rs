use crate::provider::ParsedSuiLog;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use indexer_framework::schema::jobs;
use indexer_framework::schema::rate_revisions;
use indexer_framework::schema::transactions;
use serde::Deserialize;
use sui_sdk_types::Address;
use tracing::{info, instrument};

/// Sui JobOpened event structure (decoded from BCS)
///
/// NOTE: This struct must match the Sui Move event structure exactly.
/// Field order matters for BCS deserialization.
#[derive(Debug, Deserialize)]
pub struct JobOpenedEvent {
    pub job_id: u128,
    pub owner: Address,
    pub provider: Address,
    pub metadata: String,
    pub rate: u64,
    pub balance: u64,
    pub timestamp: u64,
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn handle_job_opened(conn: &mut PgConnection, parsed: &ParsedSuiLog) -> Result<()> {
    let data = parsed.bcs_contents;

    // Decode the BCS-encoded event data
    let event: JobOpenedEvent =
        bcs::from_bytes(data).context("Failed to BCS decode JobOpened event data")?;

    // Convert to appropriate string formats
    // job_id is a u128, format as hex with 0x prefix (32 hex chars for 16 bytes)
    let id = format!("0x{:032x}", event.job_id);
    let owner = event.owner.to_string();
    let provider = event.provider.to_string();
    let metadata = event.metadata;

    // Convert rate and balance to BigDecimal
    let rate = BigDecimal::from(event.rate);
    let balance = BigDecimal::from(event.balance);

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(event.timestamp);
    let timestamp_epoch = BigDecimal::from(event.timestamp);

    let mut run_duration = BigDecimal::from(0);
    let mut end_epoch = timestamp_epoch.clone();

    if &rate != &BigDecimal::from(0) {
        run_duration = (&balance / &rate).round(0);
        end_epoch = &timestamp_epoch + &run_duration;
    }

    let block = parsed.checkpoint;
    let idx = 0i64; // Sui doesn't have log index like EVM
    let tx_hash = parsed.tx_digest;

    info!(
        id,
        owner,
        provider,
        metadata,
        ?rate,
        ?balance,
        ?timestamp,
        ?timestamp_epoch,
        block,
        run_duration = run_duration.to_string(),
        end_epoch = end_epoch.to_string(),
        "creating job"
    );

    // target sql:
    // INSERT INTO jobs (id, metadata, owner, provider, rate, balance, last_settled, created, is_closed, end_epoch)
    // VALUES ("<id>", "<metadata>", "<owner>", "<provider>", "<rate>", "<balance>", "<timestamp>", "<timestamp>", false, "<end_epoch>");
    diesel::insert_into(jobs::table)
        .values((
            jobs::id.eq(&id),
            jobs::metadata.eq(&metadata),
            jobs::owner.eq(&owner),
            jobs::provider.eq(&provider),
            jobs::rate.eq(&rate),
            jobs::balance.eq(&balance),
            jobs::last_settled.eq(&timestamp),
            jobs::created.eq(&timestamp),
            jobs::is_closed.eq(false),
            jobs::end_epoch.eq(&end_epoch),
        ))
        .execute(conn)
        .context("failed to create job")?;

    // target sql:
    // INSERT INTO transactions (block, idx, job, value, is_deposit)
    // VALUES (block, idx, "<job>", "<value>", true);
    diesel::insert_into(transactions::table)
        .values((
            transactions::block.eq(block as i64),
            transactions::idx.eq(idx),
            transactions::tx_hash.eq(tx_hash),
            transactions::job.eq(&id),
            transactions::amount.eq(&balance),
            transactions::is_deposit.eq(true),
        ))
        .execute(conn)
        .context("failed to create deposit")?;

    // target sql:
    // INSERT INTO rate_revisions (job_id, value, block, timestamp)
    // VALUES ("<id>", "<rate>", "<block>", "<timestamp>");
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job_id.eq(&id),
            rate_revisions::value.eq(&rate),
            rate_revisions::block.eq(block as i64),
            rate_revisions::timestamp.eq(&timestamp_epoch),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(
        id,
        owner,
        provider,
        metadata,
        ?rate,
        ?balance,
        ?timestamp,
        block,
        run_duration = run_duration.to_string(),
        end_epoch = end_epoch.to_string(),
        "created job"
    );

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
//     fn test_create_new_job_in_empty_db() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         assert_eq!(jobs::table.count().get_result(conn), Ok(0));

//         // log under test
//         let timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
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
//                         event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)")
//                             .into(),
//                         "0x3333333333333333333333333333333333333333333333333333333333333333"
//                             .parse()?,
//                         "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
//                             .parse::<Address>()?
//                             .into_word(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     ("some metadata", 1, 2, timestamp)
//                         .abi_encode_sequence()
//                         .into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         let provider = MockProvider::new(timestamp);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(jobs::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             jobs::table.select(jobs::all_columns).first(conn),
//             Ok((
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 "some metadata".to_owned(),
//                 "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                 "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                 BigDecimal::from(1),
//                 BigDecimal::from(2),
//                 now,
//                 now,
//                 false,
//                 BigDecimal::from(timestamp + (2 * RATE_SCALING_FACTOR)),
//             ))
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .first(conn),
//             Ok((
//                 42i64,
//                 69i64,
//                 keccak256!("some tx").encode_hex_with_prefix(),
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(2),
//                 true,
//             ))
//         );

//         assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             rate_revisions::table
//                 .select(rate_revisions::all_columns)
//                 .first(conn),
//             Ok((
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(1),
//                 42i64,
//                 BigDecimal::from(timestamp)
//             ))
//         );

//         Ok(())
//     }

//     #[test]
//     fn test_create_new_job_in_populated_db() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         let original_timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let original_now =
//             std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
//         diesel::insert_into(jobs::table)
//             .values((
//                 jobs::id.eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
//                 jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
//                 jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
//                 jobs::metadata.eq("some other metadata"),
//                 jobs::rate.eq(BigDecimal::from(3)),
//                 jobs::balance.eq(BigDecimal::from(21)),
//                 jobs::last_settled.eq(&original_now),
//                 jobs::created.eq(&original_now),
//                 jobs::is_closed.eq(false),
//                 jobs::end_epoch.eq(BigDecimal::from(
//                     original_timestamp + (7 * RATE_SCALING_FACTOR),
//                 )),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;

//         diesel::insert_into(transactions::table)
//             .values((
//                 transactions::block.eq(123),
//                 transactions::idx.eq(5),
//                 transactions::tx_hash
//                     .eq("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
//                 transactions::job
//                     .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
//                 transactions::amount.eq(BigDecimal::from(10)),
//                 transactions::is_deposit.eq(false),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;

//         assert_eq!(jobs::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             jobs::table.select(jobs::all_columns).first(conn),
//             Ok((
//                 "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                 "some other metadata".to_owned(),
//                 "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                 "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                 BigDecimal::from(3),
//                 BigDecimal::from(21),
//                 original_now,
//                 original_now,
//                 false,
//                 BigDecimal::from(original_timestamp + (7 * RATE_SCALING_FACTOR)),
//             ))
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .first(conn),
//             Ok((
//                 123i64,
//                 5i64,
//                 "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
//                 "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                 BigDecimal::from(10),
//                 false,
//             ))
//         );

//         // log under test
//         let timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
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
//                         event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)")
//                             .into(),
//                         "0x3333333333333333333333333333333333333333333333333333333333333333"
//                             .parse()?,
//                         "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
//                             .parse::<Address>()?
//                             .into_word(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     ("some metadata", 1, 2, timestamp)
//                         .abi_encode_sequence()
//                         .into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         let provider = MockProvider::new(timestamp);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(jobs::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             jobs::table
//                 .select(jobs::all_columns)
//                 .order_by(jobs::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                     "some metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(1),
//                     BigDecimal::from(2),
//                     now,
//                     now,
//                     false,
//                     BigDecimal::from(timestamp + (2 * RATE_SCALING_FACTOR)),
//                 ),
//                 (
//                     "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                     "some other metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(3),
//                     BigDecimal::from(21),
//                     original_now,
//                     original_now,
//                     false,
//                     BigDecimal::from(original_timestamp + (7 * RATE_SCALING_FACTOR)),
//                 )
//             ])
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .order_by((transactions::block, transactions::idx))
//                 .load(conn),
//             Ok(vec![
//                 (
//                     42i64,
//                     69i64,
//                     keccak256!("some tx").encode_hex_with_prefix(),
//                     "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                     BigDecimal::from(2),
//                     true,
//                 ),
//                 (
//                     123i64,
//                     5i64,
//                     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
//                     "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                     BigDecimal::from(10),
//                     false,
//                 )
//             ])
//         );

//         assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));

//         assert_eq!(
//             rate_revisions::table
//                 .select(rate_revisions::all_columns)
//                 .load(conn),
//             Ok(vec![(
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(1),
//                 42i64,
//                 BigDecimal::from(timestamp)
//             )])
//         );

//         Ok(())
//     }

//     #[test]
//     fn test_create_new_job_when_rate_is_0() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         let timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
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
//                         event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)")
//                             .into(),
//                         "0x3333333333333333333333333333333333333333333333333333333333333333"
//                             .parse()?,
//                         "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
//                             .parse::<Address>()?
//                             .into_word(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     ("some metadata", 0, 2, timestamp)
//                         .abi_encode_sequence()
//                         .into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         let provider = MockProvider::new(timestamp);
//         // use handle_log instead of concrete handler to test dispatch
//         handle_log(conn, log, &provider)?;

//         // checks
//         assert_eq!(jobs::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             jobs::table.select(jobs::all_columns).first(conn),
//             Ok((
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 "some metadata".to_owned(),
//                 "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                 "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                 BigDecimal::from(0),
//                 BigDecimal::from(2),
//                 now,
//                 now,
//                 false,
//                 BigDecimal::from(timestamp),
//             ))
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .first(conn),
//             Ok((
//                 42i64,
//                 69i64,
//                 keccak256!("some tx").encode_hex_with_prefix(),
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(2),
//                 true,
//             ))
//         );

//         assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             rate_revisions::table
//                 .select(rate_revisions::all_columns)
//                 .first(conn),
//             Ok((
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(0),
//                 42i64,
//                 BigDecimal::from(timestamp)
//             ))
//         );

//         Ok(())
//     }
//     #[test]
//     fn test_create_new_job_when_it_already_exists() -> Result<()> {
//         // setup
//         let mut db = TestDb::new();
//         let conn = &mut db.conn;

//         let contract = "0x1111111111111111111111111111111111111111".parse()?;

//         let original_timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let original_now =
//             std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
//         diesel::insert_into(jobs::table)
//             .values((
//                 jobs::id.eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
//                 jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
//                 jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
//                 jobs::metadata.eq("some other metadata"),
//                 jobs::rate.eq(BigDecimal::from(3)),
//                 jobs::balance.eq(BigDecimal::from(21)),
//                 jobs::last_settled.eq(&original_now),
//                 jobs::created.eq(&original_now),
//                 jobs::is_closed.eq(false),
//                 jobs::end_epoch.eq(BigDecimal::from(
//                     original_timestamp + (7 * RATE_SCALING_FACTOR),
//                 )),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;
//         let timestamp = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)?
//             .as_secs();
//         // we do this after the timestamp to truncate beyond seconds
//         let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
//         diesel::insert_into(jobs::table)
//             .values((
//                 jobs::id.eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
//                 jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
//                 jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
//                 jobs::metadata.eq("some metadata"),
//                 jobs::rate.eq(BigDecimal::from(1)),
//                 jobs::balance.eq(BigDecimal::from(2)),
//                 jobs::last_settled.eq(&now),
//                 jobs::created.eq(&now),
//                 jobs::is_closed.eq(false),
//                 jobs::end_epoch.eq(BigDecimal::from(timestamp + (2 * RATE_SCALING_FACTOR))),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;

//         diesel::insert_into(transactions::table)
//             .values((
//                 transactions::block.eq(123),
//                 transactions::idx.eq(5),
//                 transactions::tx_hash
//                     .eq("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
//                 transactions::job
//                     .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
//                 transactions::amount.eq(BigDecimal::from(10)),
//                 transactions::is_deposit.eq(false),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;

//         diesel::insert_into(rate_revisions::table)
//             .values((
//                 rate_revisions::job_id
//                     .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
//                 rate_revisions::value.eq(BigDecimal::from(1)),
//                 rate_revisions::block.eq(42i64),
//                 rate_revisions::timestamp.eq(BigDecimal::from(timestamp)),
//             ))
//             .execute(conn)
//             .context("failed to create job")?;

//         assert_eq!(jobs::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             jobs::table
//                 .select(jobs::all_columns)
//                 .order_by(jobs::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                     "some metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(1),
//                     BigDecimal::from(2),
//                     now,
//                     now,
//                     false,
//                     BigDecimal::from(timestamp + (2 * RATE_SCALING_FACTOR)),
//                 ),
//                 (
//                     "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                     "some other metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(3),
//                     BigDecimal::from(21),
//                     original_now,
//                     original_now,
//                     false,
//                     BigDecimal::from(original_timestamp + (7 * RATE_SCALING_FACTOR)),
//                 )
//             ])
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .first(conn),
//             Ok((
//                 123i64,
//                 5i64,
//                 "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(10),
//                 false,
//             ))
//         );

//         assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             rate_revisions::table
//                 .select(rate_revisions::all_columns)
//                 .load(conn),
//             Ok(vec![(
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(1),
//                 42i64,
//                 BigDecimal::from(timestamp)
//             )])
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
//                         event!("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)")
//                             .into(),
//                         "0x3333333333333333333333333333333333333333333333333333333333333333"
//                             .parse()?,
//                         "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
//                             .parse::<Address>()?
//                             .into_word(),
//                         "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
//                             .parse::<Address>()?
//                             .into_word(),
//                     ],
//                     ("some metadata", 1, 2, timestamp)
//                         .abi_encode_sequence()
//                         .into(),
//                 )
//                 .unwrap(),
//             },
//         };

//         let provider = MockProvider::new(timestamp);
//         // use handle_log instead of concrete handler to test dispatch
//         let res = handle_log(conn, log, &provider);

//         // checks
//         assert_eq!(
//             format!("{:?}", res.unwrap_err()),
//             "failed to create job\n\nCaused by:\n    duplicate key value violates unique constraint \"jobs_pkey\""
//         );
//         assert_eq!(jobs::table.count().get_result(conn), Ok(2));
//         assert_eq!(
//             jobs::table
//                 .select(jobs::all_columns)
//                 .order_by(jobs::id)
//                 .load(conn),
//             Ok(vec![
//                 (
//                     "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                     "some metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(1),
//                     BigDecimal::from(2),
//                     now,
//                     now,
//                     false,
//                     BigDecimal::from(timestamp + (2 * RATE_SCALING_FACTOR)),
//                 ),
//                 (
//                     "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
//                     "some other metadata".to_owned(),
//                     "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
//                     "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
//                     BigDecimal::from(3),
//                     BigDecimal::from(21),
//                     original_now,
//                     original_now,
//                     false,
//                     BigDecimal::from(original_timestamp + (7 * RATE_SCALING_FACTOR)),
//                 )
//             ])
//         );

//         assert_eq!(transactions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             transactions::table
//                 .select(transactions::all_columns)
//                 .first(conn),
//             Ok((
//                 123i64,
//                 5i64,
//                 "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(10),
//                 false,
//             ))
//         );

//         assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
//         assert_eq!(
//             rate_revisions::table
//                 .select(rate_revisions::all_columns)
//                 .load(conn),
//             Ok(vec![(
//                 "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
//                 BigDecimal::from(1),
//                 42i64,
//                 BigDecimal::from(timestamp),
//             )])
//         );

//         Ok(())
//     }
// }
