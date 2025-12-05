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

#[cfg(test)]
mod test {
    use crate::handlers::handle_log;
    use crate::handlers::test_db::TestDb;
    use crate::schema::proposals;
    use crate::Proposal;
    use crate::ResultOutcome;
    use alloy::{primitives::LogData, rpc::types::Log};
    use diesel::prelude::*;
    use diesel::RunQueryDsl;
    use ethp::{event, keccak256};

    use super::*;

    #[test]
    fn test_vote_submitted_when_proposal_exists() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Pending),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 0, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks

        assert_eq!(votes::table.count().get_result(conn), Ok(1));
        assert_eq!(
            votes::table.select(votes::all_columns).first(conn),
            Ok((
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                keccak256!("some tx").encode_hex_with_prefix(),
                BigDecimal::from(421614),
                BigDecimal::from(0),
            ))
        );

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        Ok(())
    }

    #[test]
    fn test_vote_submitted_when_proposal_does_not_exist() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Pending),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 0, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(votes::table.count().get_result(conn), Ok(0));

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        Ok(())
    }

    #[test]
    fn test_vote_submitted_when_proposal_is_not_pending() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Passed,
            }
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 0, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(votes::table.count().get_result(conn), Ok(0));

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Passed,
            }
        );

        Ok(())
    }

    #[test]
    fn test_vote_submitted_when_proposal_is_already_executed() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(true),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: true,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Passed,
            }
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 0, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(votes::table.count().get_result(conn), Ok(0));

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: true,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Passed,
            }
        );

        Ok(())
    }

    #[test]
    fn test_vote_submitted_when_voting_for_same_proposal_twice() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Pending),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        diesel::insert_into(votes::table)
            .values((
                votes::proposal_id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                votes::voter.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                votes::delegator.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                votes::tx_hash.eq(keccak256!("first tx").encode_hex_with_prefix()),
                votes::delegator_chain_id.eq(BigDecimal::from(421614)),
                votes::vote_idx.eq(BigDecimal::from(0)),
            ))
            .execute(conn)
            .context("failed to create vote")?;

        assert_eq!(votes::table.count().get_result(conn), Ok(1));
        assert_eq!(
            votes::table.select(votes::all_columns).first(conn),
            Ok((
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                keccak256!("first tx").encode_hex_with_prefix(),
                BigDecimal::from(421614),
                BigDecimal::from(0),
            ))
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 1, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(votes::table.count().get_result(conn), Ok(1));
        assert_eq!(
            votes::table.select(votes::all_columns).first(conn),
            Ok((
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                keccak256!("some tx").encode_hex_with_prefix(),
                BigDecimal::from(421614),
                BigDecimal::from(1),
            ))
        );

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        Ok(())
    }

    #[test]
    fn test_vote_submitted_when_voting_for_same_proposal_twice_with_different_delegator(
    ) -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Pending),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        diesel::insert_into(votes::table)
            .values((
                votes::proposal_id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                votes::voter.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                votes::delegator.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                votes::tx_hash.eq(keccak256!("first tx").encode_hex_with_prefix()),
                votes::delegator_chain_id.eq(BigDecimal::from(421614)),
                votes::vote_idx.eq(BigDecimal::from(0)),
            ))
            .execute(conn)
            .context("failed to create vote")?;

        assert_eq!(votes::table.count().get_result(conn), Ok(1));
        assert_eq!(
            votes::table.select(votes::all_columns).first(conn),
            Ok((
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                keccak256!("first tx").encode_hex_with_prefix(),
                BigDecimal::from(421614),
                BigDecimal::from(0),
            ))
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
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("VoteSubmitted(bytes32,address,address,uint256,uint256,bytes)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                        "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (421614, 1, Bytes::new()).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(votes::table.count().get_result(conn), Ok(1));
        assert_eq!(
            votes::table.select(votes::all_columns).first(conn),
            Ok((
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC".to_owned(),
                keccak256!("some tx").encode_hex_with_prefix(),
                BigDecimal::from(421614),
                BigDecimal::from(1),
            ))
        );

        assert_eq!(proposals::table.count().get_result(conn), Ok(1));
        assert_eq!(
            proposals::table
                .select(Proposal::as_select())
                .first(conn)
                .unwrap(),
            Proposal {
                id: "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                proposer: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                nonce: BigDecimal::from(12),
                targets: Vec::<String>::new(),
                values: Vec::<BigDecimal>::new(),
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(1),
                proposal_end_time: BigDecimal::from(4),
                voting_start_time: BigDecimal::from(2),
                voting_end_time: BigDecimal::from(3),
                outcome: ResultOutcome::Pending,
            }
        );

        Ok(())
    }
}
