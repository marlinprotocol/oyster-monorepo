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
