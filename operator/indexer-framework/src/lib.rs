pub mod chain;
pub mod events;
pub mod repository;
pub mod schema;

use std::cmp::min;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tracing::{debug, info, instrument}; // TODO: keep or replace with custom errors

use chain::ChainHandler;
use repository::Repository;

// Define generic trait for safe integer conversions
pub trait SaturatingConvert<T> {
    fn saturating_to(self) -> T;
}

// usize -> i64
impl SaturatingConvert<i64> for usize {
    fn saturating_to(self) -> i64 {
        if self > i64::MAX as usize {
            i64::MAX
        } else {
            self as i64
        }
    }
}

// u64 -> i64
impl SaturatingConvert<i64> for u64 {
    fn saturating_to(self) -> i64 {
        if self > i64::MAX as u64 {
            i64::MAX
        } else {
            self as i64
        }
    }
}

// i64 -> u64
impl SaturatingConvert<u64> for i64 {
    fn saturating_to(self) -> u64 {
        if self < 0 {
            0
        } else {
            self as u64
        }
    }
}

// TODO: add custom errors
#[instrument(level = "info", skip_all, parent = None)]
pub async fn run(repo: Repository, rpc_client: impl ChainHandler, range_size: u64) -> Result<()> {
    let retry_strategy = ExponentialBackoff::from_millis(500)
        .max_delay(Duration::from_secs(10))
        .map(jitter);

    // fetch last updated block from the db
    let mut last_processed_block_id = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_last_processed_block().await
    })
    .await
    .context(
        "No last processed block found, should never happen unless the database is corrupted",
    )?;

    info!(block = last_processed_block_id, "last processed");

    let mut active_job_ids = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_active_jobs().await
    })
    .await?;

    loop {
        let latest_block = rpc_client
            .fetch_latest_block()
            .await
            .context("Failed to fetch latest block from the rpc")?;
        let latest_block_i64: i64 = latest_block.saturating_to();

        info!(block = latest_block, "latest block");

        // should not really ever be true
        // effectively means the rpc was rolled back
        if latest_block_i64 < last_processed_block_id {
            return Err(anyhow!(
                "rpc is behind the db, should never happen unless the rpc was rolled back"
            ));
        }

        if latest_block_i64 == last_processed_block_id {
            // we are up to date, simply sleep for a bit
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        // start from the next block to what has already been processed
        let start_block: u64 = (last_processed_block_id + 1).saturating_to();
        // cap block range using range_size
        // might need some babysitting during initial sync
        let end_block = min(start_block + range_size - 1, latest_block);

        info!(start_block, end_block, "fetching range");

        let block_logs = rpc_client
            .fetch_logs_and_group_by_block(start_block, end_block)
            .await
            .context("Failed to fetch logs from the rpc")?;

        info!(start_block, end_block, "processing range");

        for (block_number, logs) in block_logs.iter() {
            info!(
                block_number,
                logs_count = logs.len(),
                "processing block logs"
            );

            let records = rpc_client
                .process_logs_in_block(*block_number, logs, &mut active_job_ids)
                .context("Failed to process logs in a block")?;

            Retry::spawn(retry_strategy.clone(), || async {
                let mut tx = repo.pool.begin().await?;
                let inserted_batch = repo.insert_events(&mut tx, records.clone()).await?;
                debug!(block_number, inserted_batch, "batch of block logs inserted");
                let updated = repo
                    .update_state(&mut tx, (*block_number).saturating_to())
                    .await?;
                debug!("is_last_set: {}", updated == 1);
                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("Failed to batch insert logs for a block in the DB")?;
        }

        last_processed_block_id = end_block.saturating_to();
    }
}
