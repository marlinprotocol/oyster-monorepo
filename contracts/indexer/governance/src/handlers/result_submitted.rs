use alloy::hex::ToHexExt;
use alloy::primitives::U256;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::deserialize::FromSqlRow;
use diesel::expression::AsExpression;
use diesel::pg::Pg;
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use std::io::Write;
use std::str::FromStr;
use tracing::warn;
use tracing::{info, instrument};

use crate::schema::results;

#[derive(Debug, AsExpression, FromSqlRow)]
#[diesel(sql_type = crate::schema::sql_types::ResultOutcome)]
pub enum ResultOutcome {
    Pending,
    Passed,
    Failed,
    Vetoed,
}

impl ToSql<crate::schema::sql_types::ResultOutcome, Pg> for ResultOutcome {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        match *self {
            ResultOutcome::Pending => out.write_all(b"PENDING")?,
            ResultOutcome::Passed => out.write_all(b"PASSED")?,
            ResultOutcome::Failed => out.write_all(b"FAILED")?,
            ResultOutcome::Vetoed => out.write_all(b"VETOED")?,
        }
        Ok(IsNull::No)
    }
}

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_result_submitted(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing result submitted");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    let ((yes, no, abstain, no_with_veto, total_voting_power), outcome) =
        <((U256, U256, U256, U256, U256), U256)>::abi_decode_sequence(&log.data().data, true)?;

    // Convert U256 values to BigDecimal for database storage
    let (yes, no, abstain, no_with_veto, total_voting_power) = (
        BigDecimal::from_str(&yes.to_string())?,
        BigDecimal::from_str(&no.to_string())?,
        BigDecimal::from_str(&abstain.to_string())?,
        BigDecimal::from_str(&no_with_veto.to_string())?,
        BigDecimal::from_str(&total_voting_power.to_string())?,
    );

    let outcome_enum = match outcome.to::<u8>() {
        0 => ResultOutcome::Pending,
        1 => ResultOutcome::Passed,
        2 => ResultOutcome::Failed,
        3 => ResultOutcome::Vetoed,
        _ => ResultOutcome::Pending,
    };

    info!(
        ?proposal_id,
        ?tx_hash,
        ?yes,
        ?no,
        ?abstain,
        ?no_with_veto,
        ?total_voting_power,
        ?outcome_enum,
        "creating result"
    );

    diesel::insert_into(results::table)
        .values((
            results::proposal_id.eq(&proposal_id),
            results::yes.eq(&yes),
            results::no.eq(&no),
            results::abstain.eq(&abstain),
            results::no_with_veto.eq(&no_with_veto),
            results::total_voting_power.eq(&total_voting_power),
            results::outcome.eq(&outcome_enum),
            results::tx_hash.eq(&tx_hash),
        ))
        .execute(conn)
        .context("failed to insert result")?;

    info!(?proposal_id, ?tx_hash, ?outcome_enum, "result created");

    Ok(())
}
