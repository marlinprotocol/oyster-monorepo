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

    // Convert arrays for database storage
    let targets: Vec<String> = targets.iter().map(|addr| addr.to_checksum(None)).collect();
    let values: Vec<BigDecimal> = values
        .iter()
        .map(|v| BigDecimal::from_str(&v.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let calldatas: Vec<String> = calldatas
        .iter()
        .map(|bytes| bytes.encode_hex_with_prefix())
        .collect();

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
    // INSERT INTO proposals (id, proposer, nonce, targets, values, calldatas, title, description, tx_hash, executed, proposal_created_at, proposal_end_time, voting_start_time, voting_end_time, outcome)
    // VALUES ("<id>", "<proposer>", "<nonce>", ARRAY["<targets>"], ARRAY["<values>"], ARRAY["<calldatas>"], "<title>", "<description>", "<tx_hash>", "<executed>", "<start_timestamp>", "<proposal_deadline>", "<vote_activation_timestamp>", "<vote_deadline>", "PENDING");
    diesel::insert_into(proposals::table)
        .values((
            proposals::id.eq(&proposal_id),
            proposals::proposer.eq(&proposer),
            proposals::nonce.eq(&nonce),
            proposals::targets.eq(&targets),
            proposals::values.eq(&values),
            proposals::calldatas.eq(&calldatas),
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
    fn test_proposal_created_in_empty_db() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(proposals::table.count().get_result(conn), Ok(0));

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
                        event!("ProposalCreated(bytes32,address,uint256,address[],uint256[],bytes[],string,string,(uint256,uint256,uint256,uint256))")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                   (12, vec!["0x1111111111111111111111111111111111111111".parse::<Address>()?, "0x2222222222222222222222222222222222222222".parse::<Address>()?], vec!["1".parse::<U256>()?, "2".parse::<U256>()?], Vec::<Bytes>::new(), 
                   "some title".as_bytes().to_vec(), "some description".as_bytes().to_vec(), (3, 4, 5, 6)
                ).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
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
                targets: vec![
                    "0x1111111111111111111111111111111111111111".to_owned(),
                    "0x2222222222222222222222222222222222222222".to_owned()
                ],
                values: vec![BigDecimal::from(1), BigDecimal::from(2)],
                calldatas: Vec::<String>::new(),
                title: "some title".to_owned(),
                description: "some description".to_owned(),
                tx_hash: keccak256!("some tx").encode_hex_with_prefix(),
                executed: false,
                proposal_created_at: BigDecimal::from(3),
                proposal_end_time: BigDecimal::from(6),
                voting_start_time: BigDecimal::from(4),
                voting_end_time: BigDecimal::from(5),
                outcome: ResultOutcome::Pending,
            }
        );

        Ok(())
    }

    #[test]
    fn test_proposal_created_in_populated_db() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
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
            block_hash: Some(keccak256!("txn block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("txn hash").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("ProposalCreated(bytes32,address,uint256,address[],uint256[],bytes[],string,string,(uint256,uint256,uint256,uint256))")
                            .into(),
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                            .parse()?,
                        "0xccBcCCCCCCcCCCcCcCcCcCcccCccCCccccccCCcC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                   (14, vec!["0x1111111111111111111111111111111111111111".parse::<Address>()?, "0x2222222222222222222222222222222222222222".parse::<Address>()?], vec!["1".parse::<U256>()?, "2".parse::<U256>()?], Vec::<Bytes>::new(),
                   "new title".as_bytes().to_vec(), "new description".as_bytes().to_vec(), (7, 8, 9, 10)
                ).abi_encode_sequence().into(),
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
                .select(Proposal::as_select())
                .order_by(proposals::id)
                .load(conn)
                .unwrap(),
            vec![
                Proposal {
                    id: "0x3333333333333333333333333333333333333333333333333333333333333333"
                        .to_owned(),
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
                },
                Proposal {
                    id: "0x4444444444444444444444444444444444444444444444444444444444444444"
                        .to_owned(),
                    proposer: "0xccBcCCCCCCcCCCcCcCcCcCcccCccCCccccccCCcC".to_owned(),
                    nonce: BigDecimal::from(14),
                    targets: vec![
                        "0x1111111111111111111111111111111111111111".to_owned(),
                        "0x2222222222222222222222222222222222222222".to_owned()
                    ],
                    values: vec![BigDecimal::from(1), BigDecimal::from(2)],
                    calldatas: Vec::<String>::new(),
                    title: "new title".to_owned(),
                    description: "new description".to_owned(),
                    tx_hash: keccak256!("txn hash").encode_hex_with_prefix(),
                    executed: false,
                    proposal_created_at: BigDecimal::from(7),
                    proposal_end_time: BigDecimal::from(10),
                    voting_start_time: BigDecimal::from(8),
                    voting_end_time: BigDecimal::from(9),
                    outcome: ResultOutcome::Pending,
                }
            ]
        );

        Ok(())
    }

    #[test]
    fn test_proposal_created_with_null_chars_in_title_and_description() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
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
            block_hash: Some(keccak256!("txn block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("txn hash").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("ProposalCreated(bytes32,address,uint256,address[],uint256[],bytes[],string,string,(uint256,uint256,uint256,uint256))")
                            .into(),
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                            .parse()?,
                        "0xccBcCCCCCCcCCCcCcCcCcCcccCccCCccccccCCcC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                   (14, vec!["0x1111111111111111111111111111111111111111".parse::<Address>()?, "0x2222222222222222222222222222222222222222".parse::<Address>()?], vec!["1".parse::<U256>()?, "2".parse::<U256>()?], Vec::<Bytes>::new(),
                   "new \0title\0".as_bytes().to_vec(), "new \0description\0\0\0\0\0".as_bytes().to_vec(), (7, 8, 9, 10)
                ).abi_encode_sequence().into(),
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
                .select(Proposal::as_select())
                .order_by(proposals::id)
                .load(conn)
                .unwrap(),
            vec![
                Proposal {
                    id: "0x3333333333333333333333333333333333333333333333333333333333333333"
                        .to_owned(),
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
                },
                Proposal {
                    id: "0x4444444444444444444444444444444444444444444444444444444444444444"
                        .to_owned(),
                    proposer: "0xccBcCCCCCCcCCCcCcCcCcCcccCccCCccccccCCcC".to_owned(),
                    nonce: BigDecimal::from(14),
                    targets: vec![
                        "0x1111111111111111111111111111111111111111".to_owned(),
                        "0x2222222222222222222222222222222222222222".to_owned()
                    ],
                    values: vec![BigDecimal::from(1), BigDecimal::from(2)],
                    calldatas: Vec::<String>::new(),
                    title: "new title".to_owned(),
                    description: "new description".to_owned(),
                    tx_hash: keccak256!("txn hash").encode_hex_with_prefix(),
                    executed: false,
                    proposal_created_at: BigDecimal::from(7),
                    proposal_end_time: BigDecimal::from(10),
                    voting_start_time: BigDecimal::from(8),
                    voting_end_time: BigDecimal::from(9),
                    outcome: ResultOutcome::Pending,
                }
            ]
        );

        Ok(())
    }

    #[test]
    fn test_proposal_created_when_it_already_exists() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let governance_contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(proposals::table)
            .values((
                proposals::id
                    .eq("0x3333333333333333333333333333333333333333333333333333333333333333"),
                proposals::proposer.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                proposals::nonce.eq(BigDecimal::from(12)),
                proposals::targets.eq(Vec::<String>::new()),
                proposals::values.eq(Vec::<BigDecimal>::new()),
                proposals::calldatas.eq(Vec::<String>::new()),
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
            block_hash: Some(keccak256!("txn block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("txn hash").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: governance_contract,
                data: LogData::new(
                    vec![
                        event!("ProposalCreated(bytes32,address,uint256,address[],uint256[],bytes[],string,string,(uint256,uint256,uint256,uint256))")
                            .into(),
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .parse()?,
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                   (12, vec!["0x3333333333333333333333333333333333333333".parse::<Address>()?, "0x4444444444444444444444444444444444444444".parse::<Address>()?], vec!["3".parse::<U256>()?, "4".parse::<U256>()?], Vec::<Bytes>::new(),
                   "some title".as_bytes().to_vec(), "some description".as_bytes().to_vec(), (7, 8, 9, 10)
                ).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);

        // checks
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to create proposal\n\nCaused by:\n    duplicate key value violates unique constraint \"proposals_pkey\""
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
