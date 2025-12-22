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

    let outcome_code = outcome.to::<u8>();
    let outcome_enum = ResultOutcome::from_code(outcome_code).unwrap_or_else(|| {
        warn!(
            code = outcome_code,
            "unknown outcome code, defaulting to pending"
        );
        ResultOutcome::Pending
    });

    info!(
        ?proposal_id,
        ?tx_hash,
        ?yes,
        ?no,
        ?abstain,
        ?no_with_veto,
        ?total_voting_power,
        ?outcome_enum,
        "submitting result"
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

    info!(?proposal_id, ?tx_hash, ?outcome_enum, "result submitted");

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::handlers::handle_log;
    use crate::handlers::test_db::TestDb;
    use crate::Proposal;
    use alloy::{primitives::LogData, rpc::types::Log};
    use diesel::prelude::*;
    use diesel::RunQueryDsl;
    use ethp::{event, keccak256};

    use super::*;

    #[test]
    fn test_result_submitted_when_proposal_exists() -> Result<()> {
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
                        event!("ResultSubmitted(bytes32,(uint256,uint256,uint256,uint256,uint256),uint8)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                   ((3, 4, 5, 6, 7), 2).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(results::table.count().get_result(conn), Ok(1));
        assert_eq!(
            results::table
                .select(results::all_columns)
                .order_by(results::proposal_id)
                .load(conn),
            Ok(vec![(
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                BigDecimal::from(3),
                BigDecimal::from(4),
                BigDecimal::from(5),
                BigDecimal::from(6),
                BigDecimal::from(7),
                keccak256!("some tx").encode_hex_with_prefix(),
            )])
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
                outcome: ResultOutcome::Failed,
            }
        );

        Ok(())
    }

    #[test]
    fn test_result_submitted_when_proposal_does_not_exist() -> Result<()> {
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
                        event!("ResultSubmitted(bytes32,(uint256,uint256,uint256,uint256,uint256),uint8)")
                            .into(),
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                            .parse()?,
                    ],
                   ((3, 4, 5, 6, 7), 2).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(results::table.count().get_result(conn), Ok(0));

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
    fn test_result_submitted_when_proposal_is_not_pending() -> Result<()> {
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
                        event!("ResultSubmitted(bytes32,(uint256,uint256,uint256,uint256,uint256),uint8)")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                   ((3, 4, 5, 6, 7), 2).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(results::table.count().get_result(conn), Ok(0));

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
    fn test_result_submitted_when_result_is_unexpected() -> Result<()> {
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
                        event!("ResultSubmitted(bytes32,(uint256,uint256,uint256,uint256,uint256),uint8)")
                            .into(),
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                            .parse()?,
                    ],
                   ((3, 4, 5, 6, 7), 9).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(results::table.count().get_result(conn), Ok(0));

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
