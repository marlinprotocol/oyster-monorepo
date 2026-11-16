pub mod schema;

use std::time::Duration;

use alloy::rpc::types::eth::Log;
use anyhow::{anyhow, Context, Result};
use diesel::prelude::*;
use diesel_migrations::embed_migrations;
use diesel_migrations::EmbeddedMigrations;
use tracing::{info, instrument};

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

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

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
    // fetch last updated block from the db
    let mut last_updated = last_synced_block(conn)?;

    info!(block = last_updated, "last updated");

    loop {
        // fetch latest block from the rpc
        let latest_block = provider.latest_block()?;

        info!(block = latest_block, "latest block");

        // should not really ever be true
        // effectively means the rpc was rolled back
        if latest_block < last_updated {
            return Err(anyhow!(
                "rpc is behind the db, should never happen unless the rpc was rolled back"
            ));
        }

        if latest_block == last_updated {
            // we are up to date, simply sleep for a bit
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        // start from the next block to what has already been processed
        let start_block = last_updated + 1;
        // cap block range using range_size
        // might need some babysitting during initial sync
        let end_block = std::cmp::min(start_block + range_size - 1, latest_block);

        info!(start_block, end_block, "fetching range");

        // Use prefetched results if available, otherwise fetch normally
        let logs = provider.take_prefetched_logs(start_block, end_block)?;

        // Start prefetching the next batch in the background while we process this one.
        // This overlaps network I/O with DB processing for ~2x pipeline throughput.
        let next_start = end_block + 1;
        if next_start <= latest_block {
            let next_end = std::cmp::min(next_start + range_size - 1, latest_block);
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
                handler(conn, log, provider).context("failed to handle log")?;
            }
            set_synced_block(conn, end_block)
        })?;

        last_updated = end_block;
    }
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
