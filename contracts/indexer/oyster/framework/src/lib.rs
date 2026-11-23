pub mod schema;

use std::time::Duration;

use alloy::rpc::types::eth::Log;
use anyhow::{anyhow, Context, Result};
use diesel::prelude::*;
use diesel_migrations::embed_migrations;
use diesel_migrations::EmbeddedMigrations;
use tracing::{error, info, instrument, warn};

/// Trait for blockchain providers that can fetch logs/events and block information.
///
/// This trait abstracts over different blockchain implementations (EVM, Sui, etc.),
/// allowing the framework to work with any chain that implements these methods.
///
/// For details on implementing this trait for a new chain, see PROVIDER_PATTERN.md
pub trait LogsProvider {
    /// Get the latest block/checkpoint number from the chain.
    fn latest_block(&mut self) -> Result<u64>;
    
    /// Fetch logs/events for a block range.
    /// The implementation should convert chain-specific events to Ethereum-style Log format.
    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>>;
    
    /// Get the timestamp (in seconds since Unix epoch) for a specific block/checkpoint.
    fn block_timestamp(&self, block_number: u64) -> Result<u64>;

    /// Start prefetching logs for a range in the background.
    /// Called before processing the current batch so the next batch's fetch
    /// overlaps with current batch processing.
    /// Default implementation is a no-op (providers that don't support prefetching).
    fn start_prefetch(&self, _start_block: u64, _end_block: u64) {}

    /// Take the result of a previous prefetch, or fall back to a synchronous fetch.
    /// If a prefetch was started for the exact same range, returns those results.
    /// Otherwise, fetches synchronously via `logs()`.
    fn take_prefetched_logs(&self, start_block: u64, end_block: u64) -> Result<Vec<Log>> {
        Ok(self.logs(start_block, end_block)?.into_iter().collect())
    }
}

/// Error for failed rpc requests made by handlers through the provider.
///
/// The event loop retries the whole range when a handler fails with this error,
/// any other handler error stops the indexer.
#[derive(Debug)]
pub struct RpcError(pub String);

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RpcError {}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

// outcome of one pass of the event loop
#[derive(Debug, PartialEq)]
enum Step {
    // a range was processed and committed
    Progress,
    // nothing new on the chain
    UpToDate,
    // the rpc reports a block older than what is already indexed
    RpcBehind,
}

// errors from the rpc and database timeouts are kept apart from the rest
// they are retried, everything else stops the indexer
enum StepError {
    Rpc(anyhow::Error),
    DbTimeout(anyhow::Error),
    Fatal(anyhow::Error),
}

const IDLE_WAIT: Duration = Duration::from_secs(5);
const RPC_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RPC_BACKOFF_MAX: Duration = Duration::from_secs(60);

// limits for the queries of the indexer's own database session
// without them a lock held by another session, for example an idle transaction left open in psql,
// stops the indexer with nothing in the logs
pub const DB_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
pub const DB_STATEMENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Sets lock and statement timeouts on the session, call after the migrations have run.
///
/// A query that hits either limit fails, the event loop logs it and retries the range.
pub fn set_db_timeouts(
    conn: &mut PgConnection,
    lock_timeout: Duration,
    statement_timeout: Duration,
) -> Result<()> {
    // one statement per query, a prepared statement can not hold two
    diesel::sql_query(format!("SET lock_timeout = {}", lock_timeout.as_millis()))
        .execute(conn)
        .context("failed to set lock timeout")?;
    diesel::sql_query(format!(
        "SET statement_timeout = {}",
        statement_timeout.as_millis()
    ))
    .execute(conn)
    .context("failed to set statement timeout")?;

    Ok(())
}

// true if the error comes from a query cancelled by lock_timeout or statement_timeout
// postgres reports both as "canceling statement due to ... timeout"
fn is_db_timeout(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<diesel::result::Error>(),
            Some(diesel::result::Error::DatabaseError(_, info))
                if info.message().starts_with("canceling statement due to")
                    && info.message().ends_with("timeout")
        )
    })
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn event_loop<F, P>(
    conn: &mut PgConnection,
    provider: &mut P,
    range_size: u64,
    handler: F,
) -> Result<()>
where
    F: Fn(&mut PgConnection, Log, &P) -> Result<()>,
    P: LogsProvider,
{
    if range_size == 0 {
        return Err(anyhow!("range size must not be zero"));
    }

    // fetch last updated block from the db
    let mut last_updated = last_synced_block(conn)?;

    info!(block = last_updated, "last updated");

    let mut backoff = RPC_BACKOFF_MIN;

    loop {
        match step(conn, provider, range_size, &handler, &mut last_updated) {
            Ok(Step::Progress) => {
                backoff = RPC_BACKOFF_MIN;
            }
            Ok(Step::UpToDate) => {
                backoff = RPC_BACKOFF_MIN;
                // we are up to date, simply sleep for a bit
                std::thread::sleep(IDLE_WAIT);
            }
            Ok(Step::RpcBehind) => {
                // common with load balanced rpcs where one backend lags the others
                // wait for it to catch up
                std::thread::sleep(IDLE_WAIT);
            }
            Err(StepError::Rpc(err)) => {
                // rpc errors are expected from time to time, retry with backoff
                // nothing was written for this range, so the retry starts from the same block
                error!(?err, retry_in = ?backoff, "rpc error, will retry");
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, RPC_BACKOFF_MAX);
            }
            Err(StepError::DbTimeout(err)) => {
                // another session holds a lock the range needs, or a query ran too long
                // the range was rolled back, retry it with the same backoff as rpc errors
                error!(?err, retry_in = ?backoff, "database timeout, will retry");
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, RPC_BACKOFF_MAX);
            }
            Err(StepError::Fatal(err)) => return Err(err),
        }
    }
}

fn step<F, P>(
    conn: &mut PgConnection,
    provider: &mut P,
    range_size: u64,
    handler: &F,
    last_updated: &mut u64,
) -> Result<Step, StepError>
where
    F: Fn(&mut PgConnection, Log, &P) -> Result<()>,
    P: LogsProvider,
{
    // fetch latest block from the rpc
    let latest_block = provider
        .latest_block()
        .context("failed to fetch latest block")
        .map_err(StepError::Rpc)?;

    info!(block = latest_block, "latest block");

    if latest_block < *last_updated {
        warn!(
            rpc_block = latest_block,
            db_block = *last_updated,
            "rpc is behind the db, waiting"
        );
        return Ok(Step::RpcBehind);
    }

    if latest_block == *last_updated {
        return Ok(Step::UpToDate);
    }

    // start from the next block to what has already been processed
    let start_block = *last_updated + 1;
    // cap block range using range_size
    // might need some babysitting during initial sync
    let end_block = std::cmp::min(start_block.saturating_add(range_size - 1), latest_block);

    info!(start_block, end_block, "fetching range");

    // Use prefetched results if available, otherwise fetch normally
    let logs = provider
        .take_prefetched_logs(start_block, end_block)
        .with_context(|| format!("failed to fetch logs for blocks {start_block} to {end_block}"))
        .map_err(StepError::Rpc)?;

    // Start prefetching the next batch in the background while we process this one.
    // This overlaps network I/O with DB processing for ~2x pipeline throughput.
    let next_start = end_block + 1;
    if next_start <= latest_block {
        let next_end = std::cmp::min(next_start.saturating_add(range_size - 1), latest_block);
        info!(
            next_start_block = next_start,
            next_end_block = next_end,
            "prefetching next range"
        );
        provider.start_prefetch(next_start, next_end);
    }

    info!(start_block, end_block, "processing range");

    // execute db writes within a transaction for consistency
    // NOTE: diesel transactions are synchronous, async is not allowed inside
    // might be limiting for certain things like making rpc queries while processing logs
    // using a temporary tokio runtime is a possibility
    conn.transaction(|conn| {
        for log in logs {
            let block = log.block_number;
            let idx = log.log_index;
            handler(conn, log, provider).with_context(|| {
                format!(
                    "failed to handle log at block {}, log index {}",
                    block.map_or("unknown".to_owned(), |x| x.to_string()),
                    idx.map_or("unknown".to_owned(), |x| x.to_string()),
                )
            })?;
        }
        set_synced_block(conn, end_block)
    })
    .with_context(|| format!("failed to process blocks {start_block} to {end_block}"))
    .map_err(|err| {
        // the transaction is rolled back at this point, nothing from the range is stored
        if err.downcast_ref::<RpcError>().is_some() {
            StepError::Rpc(err)
        } else if is_db_timeout(&err) {
            StepError::DbTimeout(err)
        } else {
            StepError::Fatal(err)
        }
    })?;

    *last_updated = end_block;

    Ok(Step::Progress)
}

// the sync table has exactly one row, with id SYNC_ROW_ID
// enforced by the primary key and check constraint on id
const SYNC_ROW_ID: i32 = 1;

fn last_synced_block(conn: &mut PgConnection) -> Result<u64> {
    let block = schema::sync::table
        .filter(schema::sync::id.eq(SYNC_ROW_ID))
        .select(schema::sync::block)
        .first::<i64>(conn)
        .optional()
        .context("failed to fetch last updated block")?
        .ok_or(anyhow!(
            "no last updated block found, should never happen unless the database is corrupted"
        ))?;

    // -1 is the initial value, before any block is indexed
    Ok(block.max(0) as u64)
}

fn set_synced_block(conn: &mut PgConnection, block: u64) -> Result<()> {
    let count = diesel::update(schema::sync::table)
        .filter(schema::sync::id.eq(SYNC_ROW_ID))
        .set(schema::sync::block.eq(block as i64))
        .execute(conn)
        .context("failed to update latest block")?;

    if count != 1 {
        return Err(anyhow!(
            "sync row not found while updating latest block to {block}"
        ));
    }

    Ok(())
}

pub fn start_from(conn: &mut PgConnection, start: u64) -> Result<bool> {
    diesel::update(schema::sync::table)
        .filter(schema::sync::id.eq(SYNC_ROW_ID))
        .filter(schema::sync::block.lt(start as i64 - 1))
        .set(schema::sync::block.eq(start as i64 - 1))
        .execute(conn)
        .map(|x| x > 0)
        .context("failed to set start block")
}

#[cfg(test)]
mod tests {
    use diesel::sql_query;
    use diesel::sql_types::BigInt;
    use diesel_migrations::MigrationHarness;

    use super::*;

    // needs TEST_DATABASE_URL with a user that can create databases
    // every test gets its own database
    pub(crate) struct TestDb {
        name: String,
        pub conn: PgConnection,
    }

    fn admin_url() -> String {
        dotenvy::dotenv().ok();
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set")
    }

    impl TestDb {
        // database with only the migrations before `stop_before` applied
        pub fn new(name: &str, stop_before: Option<&str>) -> Self {
            let admin_url = admin_url();
            let name = format!("oyster_indexer_framework_test_{name}");
            let url = admin_url[..=admin_url.rfind('/').unwrap()].to_owned() + &name;

            let mut admin = PgConnection::establish(&admin_url).unwrap();
            sql_query(format!("DROP DATABASE IF EXISTS {name}"))
                .execute(&mut admin)
                .unwrap();
            sql_query(format!("CREATE DATABASE {name}"))
                .execute(&mut admin)
                .unwrap();

            let mut conn = PgConnection::establish(&url).unwrap();
            loop {
                let pending = conn.pending_migrations(MIGRATIONS).unwrap();
                let Some(next) = pending.first() else {
                    break;
                };
                if stop_before.is_some_and(|x| next.name().to_string().contains(x)) {
                    break;
                }
                conn.run_next_migration(MIGRATIONS).unwrap();
            }

            TestDb { name, conn }
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            self.conn = PgConnection::establish(&admin_url()).unwrap();
            sql_query(format!("DROP DATABASE {}", self.name))
                .execute(&mut self.conn)
                .unwrap();
        }
    }

    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    fn sync_rows(conn: &mut PgConnection) -> i64 {
        sql_query("SELECT count(*) AS count FROM sync")
            .get_result::<Count>(conn)
            .unwrap()
            .count
    }

    struct TestProvider {
        // results for successive latest_block calls
        latest: std::collections::VecDeque<Result<u64>>,
        // blocks which have one log each
        log_blocks: Vec<u64>,
        fail_logs: std::cell::Cell<u32>,
    }

    impl TestProvider {
        fn new(latest: Vec<Result<u64>>, log_blocks: Vec<u64>) -> Self {
            TestProvider {
                latest: latest.into(),
                log_blocks,
                fail_logs: 0.into(),
            }
        }
    }

    impl LogsProvider for TestProvider {
        fn latest_block(&mut self) -> Result<u64> {
            self.latest.pop_front().expect("unexpected latest_block call")
        }

        fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
            if self.fail_logs.get() > 0 {
                self.fail_logs.set(self.fail_logs.get() - 1);
                return Err(anyhow!("logs request failed"));
            }

            Ok(self
                .log_blocks
                .iter()
                .filter(|&&x| x >= start_block && x <= end_block)
                .map(|&x| Log {
                    block_number: Some(x),
                    log_index: Some(7),
                    ..Default::default()
                })
                .collect::<Vec<_>>())
        }

        fn block_timestamp(&self, _block_number: u64) -> Result<u64> {
            Ok(0)
        }
    }

    fn ok_handler(_: &mut PgConnection, _: Log, _: &TestProvider) -> Result<()> {
        Ok(())
    }

    #[test]
    fn test_step_progress_and_idle() {
        let mut db = TestDb::new("step_progress", None);
        let conn = &mut db.conn;
        let mut provider = TestProvider::new(vec![Ok(25), Ok(25), Ok(25), Ok(25)], vec![]);
        let mut last = last_synced_block(conn).unwrap();

        // ranges are capped by range size, then by the latest block
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (10, 10));
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (25, 25));
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::UpToDate)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (25, 25));
    }

    #[test]
    fn test_step_rpc_behind_db_waits() {
        let mut db = TestDb::new("step_rpc_behind", None);
        let conn = &mut db.conn;
        set_synced_block(conn, 100).unwrap();
        let mut provider = TestProvider::new(vec![Ok(98), Ok(101)], vec![]);
        let mut last = last_synced_block(conn).unwrap();

        // not an error, nothing is changed
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::RpcBehind)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (100, 100));

        // carries on once the rpc has caught up
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (101, 101));
    }

    #[test]
    fn test_step_rpc_errors_are_retryable() {
        let mut db = TestDb::new("step_rpc_errors", None);
        let conn = &mut db.conn;
        let mut provider = TestProvider::new(
            vec![Err(anyhow!("connection reset")), Ok(5), Ok(5), Ok(5)],
            vec![3],
        );
        provider.fail_logs.set(1);
        let mut last = last_synced_block(conn).unwrap();

        // latest block request fails
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Err(StepError::Rpc(_))
        ));
        // logs request fails
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Err(StepError::Rpc(_))
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (0, 0));

        // rpc request made by a handler fails, writes of the range are rolled back
        let rpc_failing_handler = |conn: &mut PgConnection, _: Log, _: &TestProvider| {
            sql_query("UPDATE sync SET block = 4242").execute(conn)?;
            Err(RpcError("failed to fetch timestamp".to_owned()).into())
        };
        assert!(matches!(
            step(conn, &mut provider, 10, &rpc_failing_handler, &mut last),
            Err(StepError::Rpc(_))
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (0, 0));

        // same range goes through on the next attempt
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (5, 5));
    }

    #[test]
    fn test_step_db_lock_is_retryable() {
        let mut db = TestDb::new("step_db_lock", None);
        let url = {
            let admin_url = admin_url();
            admin_url[..=admin_url.rfind('/').unwrap()].to_owned() + &db.name
        };
        let conn = &mut db.conn;
        set_db_timeouts(conn, Duration::from_millis(500), Duration::from_secs(5)).unwrap();
        let mut provider = TestProvider::new(vec![Ok(5), Ok(5)], vec![3]);
        let mut last = last_synced_block(conn).unwrap();

        // another session takes the sync row lock and keeps its transaction open
        let mut other = PgConnection::establish(&url).unwrap();
        sql_query("BEGIN").execute(&mut other).unwrap();
        sql_query("SELECT block FROM sync FOR UPDATE")
            .execute(&mut other)
            .unwrap();

        let started = std::time::Instant::now();
        let result = step(conn, &mut provider, 10, &ok_handler, &mut last);
        assert!(started.elapsed() < Duration::from_secs(5));
        let Err(StepError::DbTimeout(err)) = result else {
            panic!("expected a database timeout");
        };
        assert!(format!("{err:#}").contains("lock timeout"));
        assert_eq!(last, 0);

        // once the lock is released the same range goes through
        sql_query("ROLLBACK").execute(&mut other).unwrap();
        assert!(matches!(
            step(conn, &mut provider, 10, &ok_handler, &mut last),
            Ok(Step::Progress)
        ));
        assert_eq!((last, last_synced_block(conn).unwrap()), (5, 5));
    }

    #[test]
    fn test_step_handler_error_is_fatal_with_block_and_index() {
        let mut db = TestDb::new("step_handler_error", None);
        let conn = &mut db.conn;
        let mut provider = TestProvider::new(vec![Ok(5)], vec![3]);
        let mut last = last_synced_block(conn).unwrap();

        let failing_handler = |conn: &mut PgConnection, _: Log, _: &TestProvider| {
            sql_query("UPDATE sync SET block = 4242").execute(conn)?;
            Err(anyhow!("bad log"))
        };
        let Err(StepError::Fatal(err)) =
            step(conn, &mut provider, 10, &failing_handler, &mut last)
        else {
            panic!("expected a fatal error");
        };
        let err = format!("{err:#}");
        assert!(err.contains("block 3, log index 7"), "{err}");
        assert!(err.contains("bad log"), "{err}");

        // writes of the range are rolled back
        assert_eq!((last, last_synced_block(conn).unwrap()), (0, 0));
    }

    #[test]
    fn test_sync_has_single_row() {
        let mut db = TestDb::new("sync_single_row", None);
        let conn = &mut db.conn;

        assert_eq!(sync_rows(conn), 1);
        assert_eq!(last_synced_block(conn).unwrap(), 0);

        // a second row is rejected whatever the values are
        assert!(sql_query("INSERT INTO sync (block) VALUES (5)")
            .execute(conn)
            .is_err());
        assert!(sql_query("INSERT INTO sync (block, id) VALUES (5, 2)")
            .execute(conn)
            .is_err());
        assert_eq!(sync_rows(conn), 1);

        assert!(start_from(conn, 100).unwrap());
        assert_eq!(last_synced_block(conn).unwrap(), 99);
        // start block behind the db is ignored
        assert!(!start_from(conn, 50).unwrap());
        assert_eq!(last_synced_block(conn).unwrap(), 99);

        set_synced_block(conn, 150).unwrap();
        assert_eq!(last_synced_block(conn).unwrap(), 150);
    }

    #[test]
    fn test_sync_missing_row_is_an_error() {
        let mut db = TestDb::new("sync_missing_row", None);
        let conn = &mut db.conn;

        sql_query("DELETE FROM sync").execute(conn).unwrap();

        assert!(last_synced_block(conn).is_err());
        assert!(set_synced_block(conn, 150).is_err());
    }

    #[test]
    fn test_sync_migration_keeps_existing_block() {
        let mut db = TestDb::new("sync_migration_keeps", Some("sync_single_row"));
        let conn = &mut db.conn;

        sql_query("UPDATE sync SET block = 522111695")
            .execute(conn)
            .unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();

        assert_eq!(sync_rows(conn), 1);
        assert_eq!(last_synced_block(conn).unwrap(), 522111695);
    }

    #[test]
    fn test_sync_migration_fails_on_two_rows() {
        let mut db = TestDb::new("sync_migration_two_rows", Some("sync_single_row"));
        let conn = &mut db.conn;

        sql_query("UPDATE sync SET block = 522111695")
            .execute(conn)
            .unwrap();
        sql_query("INSERT INTO sync VALUES (452520001)")
            .execute(conn)
            .unwrap();

        let err = conn.run_pending_migrations(MIGRATIONS).unwrap_err();
        let err = format!("{err:?}");
        assert!(err.contains("sync table has 2 rows"), "{err}");

        // nothing was changed, both rows are still there for the operator to look at
        assert_eq!(sync_rows(conn), 2);
    }

    #[test]
    fn test_sync_migration_fails_on_no_rows() {
        let mut db = TestDb::new("sync_migration_no_rows", Some("sync_single_row"));
        let conn = &mut db.conn;

        sql_query("DELETE FROM sync").execute(conn).unwrap();

        let err = conn.run_pending_migrations(MIGRATIONS).unwrap_err();
        let err = format!("{err:?}");
        assert!(err.contains("sync table has 0 rows"), "{err}");
    }
}
