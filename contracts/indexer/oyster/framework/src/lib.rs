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
    let mut last_updated = schema::sync::table
        .select(schema::sync::block)
        .limit(1)
        .load::<i64>(conn)
        .context("failed to fetch last updated block")?
        .into_iter()
        .last()
        .ok_or(anyhow!(
            "no last updated block found, should never happen unless the database is corrupted"
        ))? as u64;

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
            diesel::update(schema::sync::table)
                .set(schema::sync::block.eq(end_block as i64))
                .execute(conn)
                .context("failed to update latest block")
        })?;

        last_updated = end_block;
    }
}

pub fn start_from(conn: &mut PgConnection, start: u64) -> Result<bool> {
    diesel::update(schema::sync::table)
        .filter(schema::sync::block.lt(start as i64 - 1))
        .set(schema::sync::block.eq(start as i64 - 1))
        .execute(conn)
        .map(|x| x > 0)
        .context("failed to set start block")
}
