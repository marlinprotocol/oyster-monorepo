use std::str::FromStr;

use crate::schema::proposals;
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
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_proposal_created(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing proposal created");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let proposer = Address::from_word(log.topics()[2]).to_checksum(None);

    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    let (
        nonce,
        targets,
        values,
        calldatas,
        title_bytes,
        description_bytes,
        (start_timestamp, vote_activation_timestamp, vote_deadline, proposal_deadline),
    ) = <(
        U256,
        Vec<Address>,
        Vec<U256>,
        Vec<Bytes>,
        Bytes,
        Bytes,
        (U256, U256, U256, U256),
    )>::abi_decode_sequence(&log.data().data, true)?;

    // Convert bytes -> UTF-8 and strip NULs and control chars
    fn sanitize_bytes_to_string(input: &Bytes) -> String {
        let s = String::from_utf8_lossy(input).into_owned();
        s.chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect::<String>()
            .trim_matches('\0')
            .to_string()
    }

    let title = sanitize_bytes_to_string(&title_bytes);
    let description = sanitize_bytes_to_string(&description_bytes);
    let (nonce, start_timestamp, proposal_deadline, vote_activation_timestamp, vote_deadline) = (
        BigDecimal::from_str(&nonce.to_string())?,
        BigDecimal::from_str(&start_timestamp.to_string())?,
        BigDecimal::from_str(&proposal_deadline.to_string())?,
        BigDecimal::from_str(&vote_activation_timestamp.to_string())?,
        BigDecimal::from_str(&vote_deadline.to_string())?,
    );

    info!(
        ?proposal_id,
        ?proposer,
        ?nonce,
        ?targets,
        ?values,
        ?calldatas,
        ?title,
        ?description,
        ?start_timestamp,
        ?vote_activation_timestamp,
        ?vote_deadline,
        ?proposal_deadline,
        ?tx_hash,
        "creating proposal"
    );

    // target sql:
    // INSERT INTO proposals (id, proposer, nonce, title, description, tx_hash, executed, proposal_created_at, proposal_end_time, voting_start_time, voting_end_time, outcome)
    // VALUES ("<id>", NULL, "<proposer>", "<nonce>", "<title>", "<description>", "<tx_hash>", "<executed>", "<start_timestamp>", "<proposal_deadline>", "<vote_activation_timestamp>", "<vote_deadline>", "PENDING");
    diesel::insert_into(proposals::table)
        .values((
            proposals::id.eq(&proposal_id),
            proposals::proposer.eq(&proposer),
            proposals::nonce.eq(&nonce),
            proposals::title.eq(&title),
            proposals::description.eq(&description),
            proposals::tx_hash.eq(&tx_hash),
            proposals::executed.eq(false),
            proposals::proposal_created_at.eq(&start_timestamp),
            proposals::proposal_end_time.eq(&proposal_deadline),
            proposals::voting_start_time.eq(&vote_activation_timestamp),
            proposals::voting_end_time.eq(&vote_deadline),
            proposals::outcome.eq(ResultOutcome::Pending),
        ))
        .execute(conn)
        .context("failed to create proposal")?;

    info!(
        ?proposal_id,
        ?proposer,
        ?nonce,
        ?targets,
        ?values,
        ?calldatas,
        ?title,
        ?description,
        ?start_timestamp,
        ?vote_activation_timestamp,
        ?vote_deadline,
        ?proposal_deadline,
        "proposal created"
    );

    Ok(())
}
