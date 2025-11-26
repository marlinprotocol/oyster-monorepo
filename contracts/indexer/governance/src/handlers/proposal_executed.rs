use alloy::hex::ToHexExt;
use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::{info, instrument};

use crate::schema::proposals;
use crate::ResultOutcome;

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_proposal_executed(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing proposal executed");

    let proposal_id = log.topics()[1].encode_hex_with_prefix();
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    info!(?proposal_id, ?tx_hash, "executing proposal");

    // target sql:
    // UPDATE proposals
    // SET executed = true
    // WHERE id = "<proposal_id>"
    // AND executed = false
    // AND outcome = "PASSED"
    let count = diesel::update(proposals::table)
        .filter(proposals::id.eq(&proposal_id))
        .filter(proposals::outcome.eq(ResultOutcome::Passed))
        .filter(proposals::executed.eq(false))
        .set(proposals::executed.eq(true))
        .execute(conn)
        .context("failed to update proposal execution status")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find proposal"));
    }

    info!(?proposal_id, ?tx_hash, "proposal executed");

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::handlers::handle_log;
    use crate::handlers::test_db::TestDb;
    use crate::ResultOutcome;
    use alloy::primitives::Bytes;
    use alloy::{primitives::LogData, rpc::types::Log};
    use bigdecimal::BigDecimal;
    use diesel::prelude::*;
    use diesel::RunQueryDsl;
    use ethp::{event, keccak256};

    use super::*;

    #[test]
    fn test_proposal_executed_when_proposal_exists() -> Result<()> {
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
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(2));

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
                        event!("ProposalExecuted(bytes32)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    Bytes::new(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(proposals::table.count().get_result(conn), Ok(2));
        assert_eq!(
            proposals::table
                .select(proposals::all_columns)
                .order_by(proposals::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    true,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_proposal_executed_when_proposal_does_not_exist() -> Result<()> {
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
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(2));

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
                        event!("ProposalExecuted(bytes32)").into(),
                        "0x5555555555555555555555555555555555555555555555555555555555555555"
                            .parse()?,
                    ],
                    Bytes::new(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(proposals::table.count().get_result(conn), Ok(2));
        assert_eq!(
            proposals::table
                .select(proposals::all_columns)
                .order_by(proposals::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_proposal_executed_when_proposal_is_not_passed() -> Result<()> {
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
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Pending),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(2));

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
                        event!("ProposalExecuted(bytes32)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    Bytes::new(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(proposals::table.count().get_result(conn), Ok(2));
        assert_eq!(
            proposals::table
                .select(proposals::all_columns)
                .order_by(proposals::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Pending,
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_proposal_executed_when_proposal_is_already_executed() -> Result<()> {
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
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x4444444444444444444444444444444444444444444444444444444444444444"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::title.eq("some title"),
                proposals::description.eq("some description"),
                proposals::tx_hash.eq(keccak256!("some tx").encode_hex_with_prefix()),
                proposals::executed.eq(false),
                proposals::proposal_created_at.eq(BigDecimal::from(1)),
                proposals::proposal_end_time.eq(BigDecimal::from(4)),
                proposals::voting_start_time.eq(BigDecimal::from(2)),
                proposals::voting_end_time.eq(BigDecimal::from(3)),
                proposals::outcome.eq(ResultOutcome::Passed),
            ))
            .execute(conn)
            .context("failed to create proposal")?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(2));

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
                        event!("ProposalExecuted(bytes32)").into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                    ],
                    Bytes::new(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);
        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find proposal");

        // checks
        assert_eq!(proposals::table.count().get_result(conn), Ok(2));
        assert_eq!(
            proposals::table
                .select(proposals::all_columns)
                .order_by(proposals::id)
                .load(conn),
            Ok(vec![
                (
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    true,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                ),
                (
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    BigDecimal::from(12),
                    "some title".to_owned(),
                    "some description".to_owned(),
                    keccak256!("some tx").encode_hex_with_prefix(),
                    false,
                    BigDecimal::from(1),
                    BigDecimal::from(4),
                    BigDecimal::from(2),
                    BigDecimal::from(3),
                    ResultOutcome::Passed,
                )
            ])
        );

        Ok(())
    }
}
