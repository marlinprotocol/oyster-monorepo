use crate::schema::providers;
use alloy::primitives::Address;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use diesel::query_dsl::methods::FilterDsl;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_provider_added(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let provider = Address::from_word(log.topics()[1]).to_checksum(None);
    let cp = String::abi_decode(&log.data().data, true)?;

    // we want to insert if provider does not exist
    // we want to error out if provider exists and is_active is true
    // we want to update only if is_active is false

    info!(provider, cp, "inserting provider");

    // target sql:
    // INSERT INTO providers (id, cp, is_active)
    // VALUES("<provider>", "<cp>", true)
    // ON CONFLICT (id)
    // DO UPDATE SET
    //     is_active = true
    //     cp = "<cp>"
    // WHERE is_active = false;
    let count = diesel::insert_into(providers::table)
        .values((
            providers::id.eq(&provider),
            providers::cp.eq(&cp),
            providers::is_active.eq(true),
        ))
        .on_conflict(providers::id)
        .do_update()
        .set((providers::is_active.eq(true), providers::cp.eq(&cp)))
        // we want to detect if we update any rows
        // we do it by only updating rows where is_active is false
        // and later checking if any rows were updated
        .filter(providers::is_active.eq(false))
        .execute(conn)
        .context("failed to add provider")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when there is an existing active provider
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("did not expect to find existing provider"));
    }

    info!(provider, cp, "inserted provider");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::{event, keccak256};

    use crate::handlers::handle_log;
    use crate::handlers::test_db::TestDb;

    use super::*;

    #[test]
    fn test_add_new_provider_in_empty_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(providers::table.count().get_result(conn), Ok(0));

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                "some cp".to_owned(),
                true
            ))
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_in_populated_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(1));
        assert_eq!(
            providers::table.select(providers::all_columns).first(conn),
            Ok((
                "0x7777777777777777777777777777777777777777".to_owned(),
                "some other cp".to_owned(),
                true
            ))
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_when_it_already_exists() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;
        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    true,
                )
            ])
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);

        // checks
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "did not expect to find existing provider"
        );
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_add_new_provider_when_it_is_inactive() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0x7777777777777777777777777777777777777777"),
                providers::cp.eq("some other cp"),
                providers::is_active.eq(true),
            ))
            .execute(conn)?;
        diesel::insert_into(providers::table)
            .values((
                providers::id.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                providers::cp.eq("some cp"),
                providers::is_active.eq(false),
            ))
            .execute(conn)?;

        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some cp".to_owned(),
                    false,
                )
            ])
        );

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![
                        event!("ProviderAdded(address,string)").into(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    "some random cp".abi_encode().into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(providers::table.count().get_result(conn), Ok(2));
        assert_eq!(
            providers::table
                .select(providers::all_columns)
                .order_by(providers::id)
                .load(conn),
            Ok(vec![
                (
                    "0x7777777777777777777777777777777777777777".to_owned(),
                    "some other cp".to_owned(),
                    true,
                ),
                (
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    "some random cp".to_owned(),
                    true,
                )
            ])
        );

        Ok(())
    }
}
