use crate::schema::votes;
use alloy::hex::ToHexExt;
use alloy::primitives::Address;
use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_vote_submitted(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing proposal created");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let voter = Address::from_word(log.topics()[3]).to_checksum(None);

    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    info!(?proposal_id, ?voter, ?tx_hash, "creating vote");

    // target sql:
    // INSERT INTO votes (proposal_id, voter)
    // VALUES ("<proposal_id>", "<voter>");
    diesel::insert_into(votes::table)
        .values((votes::proposal_id.eq(&proposal_id), votes::voter.eq(&voter)))
        .execute(conn)
        .context("failed to create vote")?;

    info!(?proposal_id, ?voter, "vote submitted");

    Ok(())
}
