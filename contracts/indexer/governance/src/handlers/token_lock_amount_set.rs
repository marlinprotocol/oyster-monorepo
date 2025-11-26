use std::str::FromStr;

use crate::schema::deposit_token;
use alloy::hex::ToHexExt;
use alloy::primitives::Address;
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
pub fn handle_token_lock_amount_set(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing token lock amount set");

    let (token, amount) = <(Address, U256)>::abi_decode_sequence(&log.data().data, true)?;
    let amount = BigDecimal::from_str(&amount.to_string())?;
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    info!(?token, ?amount, ?tx_hash, "setting token lock amount");

    // target sql:
    // INSERT INTO deposit_token
    // VALUES ("<address>", "<amount>")
    // ON CONFLICT (token_address) DO UPDATE SET amount = "<amount>"
    diesel::insert_into(deposit_token::table)
        .values((
            deposit_token::token_address.eq(token.to_string()),
            deposit_token::amount.eq(&amount),
        ))
        .on_conflict(deposit_token::token_address)
        .do_update()
        .set(deposit_token::amount.eq(&amount))
        .execute(conn)
        .context("failed to update deposit token amount")?;

    info!(?token, ?amount, "token lock amount set");

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::handlers::handle_log;
    use crate::handlers::test_db::TestDb;
    use alloy::{primitives::LogData, rpc::types::Log};
    use diesel::prelude::*;
    use diesel::RunQueryDsl;
    use ethp::{event, keccak256};

    use super::*;

    #[test]
    fn test_token_lock_amount_set_in_empty_db() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(deposit_token::table.count().get_result(conn), Ok(0));

        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![event!("TokenLockAmountSet(address,uint256)").into()],
                    (
                        "0x2222222222222222222222222222222222222222".parse::<Address>()?,
                        12,
                    )
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(deposit_token::table.count().get_result(conn), Ok(1));
        assert_eq!(
            deposit_token::table
                .select(deposit_token::all_columns)
                .load(conn),
            Ok(vec![(
                "0x2222222222222222222222222222222222222222".to_owned(),
                BigDecimal::from(12),
            )])
        );

        Ok(())
    }

    #[test]
    fn test_token_lock_amount_set_when_token_already_exists() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(deposit_token::table)
            .values((
                deposit_token::token_address
                    .eq("0x2222222222222222222222222222222222222222".to_owned()),
                deposit_token::amount.eq(BigDecimal::from(10)),
            ))
            .execute(conn)
            .context("failed to create deposit token")?;

        assert_eq!(deposit_token::table.count().get_result(conn), Ok(1));

        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![event!("TokenLockAmountSet(address,uint256)").into()],
                    (
                        "0x2222222222222222222222222222222222222222".parse::<Address>()?,
                        1000000,
                    )
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(deposit_token::table.count().get_result(conn), Ok(1));
        assert_eq!(
            deposit_token::table
                .select(deposit_token::all_columns)
                .load(conn),
            Ok(vec![(
                "0x2222222222222222222222222222222222222222".to_owned(),
                BigDecimal::from(1000000),
            )])
        );

        Ok(())
    }

    #[test]
    fn test_token_lock_amount_set_in_populated_db() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(deposit_token::table)
            .values((
                deposit_token::token_address
                    .eq("0x2222222222222222222222222222222222222222".to_owned()),
                deposit_token::amount.eq(BigDecimal::from(10)),
            ))
            .execute(conn)
            .context("failed to create deposit token")?;

        assert_eq!(deposit_token::table.count().get_result(conn), Ok(1));

        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![event!("TokenLockAmountSet(address,uint256)").into()],
                    (
                        "0x3333333333333333333333333333333333333333".parse::<Address>()?,
                        1000000,
                    )
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(deposit_token::table.count().get_result(conn), Ok(2));
        assert_eq!(
            deposit_token::table
                .select(deposit_token::all_columns)
                .order_by(deposit_token::token_address)
                .load(conn),
            Ok(vec![
                (
                    "0x2222222222222222222222222222222222222222".to_owned(),
                    BigDecimal::from(10),
                ),
                (
                    "0x3333333333333333333333333333333333333333".to_owned(),
                    BigDecimal::from(1000000),
                )
            ])
        );

        Ok(())
    }
}
