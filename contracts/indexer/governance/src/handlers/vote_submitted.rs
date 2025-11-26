use std::str::FromStr;

use crate::schema::proposals;
use crate::schema::votes;
use crate::ResultOutcome;
use alloy::hex::ToHexExt;
use alloy::primitives::Address;
use alloy::primitives::Bytes;
use alloy::primitives::U256;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use bigdecimal::BigDecimal;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_vote_submitted(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing proposal created");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let voter = Address::from_word(log.topics()[2]).to_checksum(None);
    let delegator = Address::from_word(log.topics()[3]).to_checksum(None);

    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    let (delegator_chain_id, vote_idx, vote_encrypted) =
        <(U256, U256, Bytes)>::abi_decode_sequence(&log.data().data, true)?;

    let (delegator_chain_id, vote_idx) = (
        BigDecimal::from_str(&delegator_chain_id.to_string())?,
        BigDecimal::from_str(&vote_idx.to_string())?,
    );

    info!(
        ?proposal_id,
        ?voter,
        ?delegator,
        ?tx_hash,
        ?delegator_chain_id,
        ?vote_idx,
        ?vote_encrypted,
        "creating vote"
    );

    // check if proposal exists with pending outcome and is not executed
    // target sql:
    // SELECT COUNT(*)
    // FROM proposals
    // WHERE id = "<proposal_id>"
    // AND outcome = "PENDING"
    // AND executed = false;
    let count = proposals::table
        .filter(proposals::id.eq(&proposal_id))
        .filter(proposals::outcome.eq(ResultOutcome::Pending))
        .filter(proposals::executed.eq(false))
        .count()
        .get_result::<i64>(conn)
        .context("failed to check if proposal exists with pending outcome")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the proposal does not exist, is no longer pending, or is already executed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find proposal"));
    }

    // target sql:
    // INSERT INTO votes (proposal_id, voter, delegator, tx_hash, delegator_chain_id)
    // VALUES ("<proposal_id>", "<voter>", "<delegator>", "<tx_hash>", "<delegator_chain_id>");
    // ON CONFLICT (proposal_id, voter)
    // DO UPDATE SET tx_hash = "<tx_hash>", delegator_chain_id = "<delegator_chain_id>", vote_idx = "<vote_idx>", delegator = "<delegator>"
    diesel::insert_into(votes::table)
        .values((
            votes::proposal_id.eq(&proposal_id),
            votes::voter.eq(&voter),
            votes::delegator.eq(&delegator),
            votes::tx_hash.eq(&tx_hash),
            votes::delegator_chain_id.eq(&delegator_chain_id),
            votes::vote_idx.eq(&vote_idx),
        ))
        .on_conflict((votes::proposal_id, votes::voter))
        .do_update()
        .set((
            votes::delegator.eq(&delegator),
            votes::tx_hash.eq(&tx_hash),
            votes::delegator_chain_id.eq(&delegator_chain_id),
            votes::vote_idx.eq(&vote_idx),
        ))
        .execute(conn)
        .context("failed to create vote")?;

    info!(?proposal_id, ?voter, "vote submitted");

    Ok(())
}
