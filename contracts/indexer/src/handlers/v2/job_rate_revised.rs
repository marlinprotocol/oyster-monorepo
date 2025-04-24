use std::str::FromStr;

use crate::schema::jobs;
use crate::schema::transactions;
use alloy::hex::ToHexExt;
use alloy::primitives::U256;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_rate_revised(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");
    let id = log.topics()[1].encode_hex_with_prefix();
    let rate = U256::abi_decode(&log.data().data, true)?;
    let rate = BigDecimal::from_str(&rate.to_string())?;

    let block = log
        .block_number
        .ok_or(anyhow!("did not get block from log"))?;
    let idx = log.log_index.ok_or(anyhow!("did not get index from log"))?;
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed
    info!(id, ?rate, "revising job rate");

    // target sql:
    // UPDATE jobs
    // SET rate = <rate>
    // WHERE id = "<id>"
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .set(jobs::rate.eq(&rate))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    // target sql:
    // INSERT INTO transactions (block, idx, job, value, tx_type)
    // VALUES (block, idx, "<job>", "<value>", "rate_revision");
    diesel::insert_into(transactions::table)
        .values((
            transactions::block.eq(block as i64),
            transactions::idx.eq(idx as i64),
            transactions::tx_hash.eq(tx_hash),
            transactions::job.eq(&id),
            transactions::amount.eq(&rate),
            transactions::tx_type.eq("rate_revision"),
        ))
        .execute(conn)
        .context("failed to create rate revision")?;

    info!(id, ?rate, "finalized job rate revision");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use bigdecimal::BigDecimal;
    use diesel::QueryDsl;
    use ethp::{event, keccak256};

    use crate::handlers::test_db::TestDb;
    use crate::handlers::v2::handle_log_v2;
    use crate::schema::{jobs, providers};

    use super::*;

    #[test]
    fn test_revise_rate_finalized() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let original_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some other metadata"),
                jobs::rate.eq(BigDecimal::from(3)),
                jobs::balance.eq(BigDecimal::from(21)),
                jobs::usdc_balance.eq(BigDecimal::from(10)),
                jobs::credits_balance.eq(BigDecimal::from(11)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(false),
            ))
            .execute(conn)
            .context("failed to create job")?;
        let creation_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let creation_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(creation_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(BigDecimal::from(1)),
                jobs::balance.eq(BigDecimal::from(20)),
                jobs::usdc_balance.eq(BigDecimal::from(19)),
                jobs::credits_balance.eq(BigDecimal::from(1)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(false),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(12),
                transactions::idx.eq(5),
                transactions::tx_hash
                    .eq("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                transactions::job
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                transactions::amount.eq(BigDecimal::from(10)),
                transactions::tx_type.eq("withdraw"),
                transactions::is_usdc.eq(true),
            ))
            .execute(conn)
            .context("failed to create job")?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(1)),
                    Some(BigDecimal::from(20)),
                    Some(creation_now),
                    Some(creation_now),
                    false,
                    Some(BigDecimal::from(19)),
                    Some(BigDecimal::from(1)),
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "some other metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(3)),
                    Some(BigDecimal::from(21)),
                    Some(original_now),
                    Some(original_now),
                    false,
                    Some(BigDecimal::from(10)),
                    Some(BigDecimal::from(11)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .first(conn),
            Ok((
                12i64,
                5i64,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                BigDecimal::from(10),
                "withdraw".to_owned(),
                Some(true),
            )),
        );

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
                        event!("JobRateRevised(bytes32,uint256)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    5.abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log_v2 instead of concrete handler to test dispatch
        handle_log_v2(conn, log)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(5)),
                    Some(BigDecimal::from(20)),
                    Some(creation_now),
                    Some(creation_now),
                    false,
                    Some(BigDecimal::from(19)),
                    Some(BigDecimal::from(1)),
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "some other metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(3)),
                    Some(BigDecimal::from(21)),
                    Some(original_now),
                    Some(original_now),
                    false,
                    Some(BigDecimal::from(10)),
                    Some(BigDecimal::from(11)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(2));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![
                (
                    12i64,
                    5i64,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    BigDecimal::from(10),
                    "withdraw".to_owned(),
                    Some(true),
                ),
                (
                    42i64,
                    69i64,
                    keccak256!("some tx").encode_hex_with_prefix(),
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    BigDecimal::from(5),
                    "rate_revision".to_owned(),
                    Some(true),
                ),
            ])
        );

        Ok(())
    }

    #[test]
    fn test_revise_rate_finalized_for_non_existent_job() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let original_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some other metadata"),
                jobs::rate.eq(BigDecimal::from(3)),
                jobs::balance.eq(BigDecimal::from(21)),
                jobs::usdc_balance.eq(BigDecimal::from(10)),
                jobs::credits_balance.eq(BigDecimal::from(11)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(false),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(12),
                transactions::idx.eq(5),
                transactions::tx_hash
                    .eq("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                transactions::job
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                transactions::amount.eq(BigDecimal::from(10)),
                transactions::tx_type.eq("withdraw"),
                transactions::is_usdc.eq(true),
            ))
            .execute(conn)
            .context("failed to create job")?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                "some other metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                Some(BigDecimal::from(3)),
                Some(BigDecimal::from(21)),
                Some(original_now),
                Some(original_now),
                false,
                Some(BigDecimal::from(10)),
                Some(BigDecimal::from(11)),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .first(conn),
            Ok((
                12i64,
                5i64,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                BigDecimal::from(10),
                "withdraw".to_owned(),
                Some(true),
            )),
        );

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
                        event!("JobRateRevised(bytes32,uint256)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    5.abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log_v2 instead of concrete handler to test dispatch
        let res = handle_log_v2(conn, log);

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![(
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                "some other metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                Some(BigDecimal::from(3)),
                Some(BigDecimal::from(21)),
                Some(original_now),
                Some(original_now),
                false,
                Some(BigDecimal::from(10)),
                Some(BigDecimal::from(11)),
            )])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![(
                12i64,
                5i64,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                BigDecimal::from(10),
                "withdraw".to_owned(),
                Some(true),
            ),])
        );

        Ok(())
    }

    #[test]
    fn test_revise_rate_finalized_on_closed_job() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        let original_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let original_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(original_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some other metadata"),
                jobs::rate.eq(BigDecimal::from(3)),
                jobs::balance.eq(BigDecimal::from(21)),
                jobs::usdc_balance.eq(BigDecimal::from(10)),
                jobs::credits_balance.eq(BigDecimal::from(11)),
                jobs::last_settled.eq(&original_now),
                jobs::created.eq(&original_now),
                jobs::is_closed.eq(false),
            ))
            .execute(conn)
            .context("failed to create job")?;
        let creation_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // we do this after the timestamp to truncate beyond seconds
        let creation_now =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(creation_timestamp);
        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(BigDecimal::from(1)),
                jobs::balance.eq(BigDecimal::from(20)),
                jobs::usdc_balance.eq(BigDecimal::from(19)),
                jobs::credits_balance.eq(BigDecimal::from(1)),
                jobs::last_settled.eq(&creation_now),
                jobs::created.eq(&creation_now),
                jobs::is_closed.eq(true),
            ))
            .execute(conn)
            .context("failed to create job")?;

        diesel::insert_into(transactions::table)
            .values((
                transactions::block.eq(12),
                transactions::idx.eq(5),
                transactions::tx_hash
                    .eq("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                transactions::job
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                transactions::amount.eq(BigDecimal::from(10)),
                transactions::tx_type.eq("withdraw"),
                transactions::is_usdc.eq(true),
            ))
            .execute(conn)
            .context("failed to create job")?;
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(1)),
                    Some(BigDecimal::from(20)),
                    Some(creation_now),
                    Some(creation_now),
                    true,
                    Some(BigDecimal::from(19)),
                    Some(BigDecimal::from(1)),
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "some other metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(3)),
                    Some(BigDecimal::from(21)),
                    Some(original_now),
                    Some(original_now),
                    false,
                    Some(BigDecimal::from(10)),
                    Some(BigDecimal::from(11)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .first(conn),
            Ok((
                12i64,
                5i64,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                BigDecimal::from(10),
                "withdraw".to_owned(),
                Some(true),
            )),
        );
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
                        event!("JobRateRevised(bytes32,uint256)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    5.abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log_v2 instead of concrete handler to test dispatch
        let res = handle_log_v2(conn, log);

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(1)),
                    Some(BigDecimal::from(20)),
                    Some(creation_now),
                    Some(creation_now),
                    true,
                    Some(BigDecimal::from(19)),
                    Some(BigDecimal::from(1)),
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "some other metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    Some(BigDecimal::from(3)),
                    Some(BigDecimal::from(21)),
                    Some(original_now),
                    Some(original_now),
                    false,
                    Some(BigDecimal::from(10)),
                    Some(BigDecimal::from(11)),
                )
            ])
        );

        assert_eq!(transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            transactions::table
                .select(transactions::all_columns)
                .order_by((transactions::block, transactions::idx))
                .load(conn),
            Ok(vec![(
                12i64,
                5i64,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                BigDecimal::from(10),
                "withdraw".to_owned(),
                Some(true),
            ),])
        );

        Ok(())
    }
}
