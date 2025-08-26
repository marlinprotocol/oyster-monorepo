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
use std::str::FromStr;
use tracing::{info, instrument, warn};

use crate::schema::proposals;
use crate::schema::results;
use crate::ResultOutcome;

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

    // target sql:
    // UPDATE proposals
    // SET outcome = "<outcome>"
    // WHERE id = "<proposal_id>"
    // AND outcome = "PENDING";
    let count = diesel::update(proposals::table)
        .filter(proposals::id.eq(&proposal_id))
        .filter(proposals::outcome.eq(ResultOutcome::Pending))
        .set(proposals::outcome.eq(&outcome_enum))
        .execute(conn)
        .context("failed to update result")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the proposal does not exist or is no longer pending
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find proposal"));
    }

    // target sql:
    // INSERT INTO results (proposal_id, yes, no, abstain, no_with_veto, total_voting_power, tx_hash)
    // VALUES ("<proposal_id>", "<yes>", "<no>", "<abstain>", "<no_with_veto>", "<total_voting_power>", "<tx_hash>");
    diesel::insert_into(results::table)
        .values((
            results::proposal_id.eq(&proposal_id),
            results::yes.eq(&yes),
            results::no.eq(&no),
            results::abstain.eq(&abstain),
            results::no_with_veto.eq(&no_with_veto),
            results::total_voting_power.eq(&total_voting_power),
            results::tx_hash.eq(&tx_hash),
        ))
        .execute(conn)
        .context("failed to insert result")?;

    info!(?proposal_id, ?tx_hash, ?outcome_enum, "result created");

    Ok(())
}
