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
use tracing::{debug, info, instrument, trace};

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
pub async fn run(
    repo: Repository,
    rpc_client: impl ChainHandler,
    start_block: Option<i64>,
    range_size: u64,
) -> Result<()> {
    info!("Applying pending migrations");
    repo.apply_migrations().await?;
    info!("Migrations applied");

    if let Some(start_block) = start_block {
        let updated = repo
            .update_state_atomic(start_block)
            .await
            .context("Failed to update start_block in the DB")?;

        debug!("Start block Updated: {}", updated == 1);
    }

    let retry_strategy = ExponentialBackoff::from_millis(500)
        .max_delay(Duration::from_secs(10))
        .map(jitter);

    let mut last_processed_block_id = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_last_processed_block().await
    })
    .await
    .context("Missing last processed block (possible DB corruption)")?;

    info!(
        last_processed_block_id,
        "Resuming from last processed block"
    );

    let mut active_job_ids = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_active_jobs().await
    })
    .await
    .context("Failed to fetch active job IDs")?;

    loop {
        let latest_block = rpc_client
            .fetch_latest_block()
            .await
            .context("RPC latest block fetch failed")?;
        let latest_block_i64: i64 = latest_block.saturating_to();

        debug!(latest_block, "Fetched latest block from RPC");

        if latest_block_i64 < last_processed_block_id {
            // warn!(db_block = last_processed_block_id, rpc_block = latest_block_i64, "RPC is behind DB (possible rollback)");
            return Err(anyhow!("RPC is behind DB (possible rollback)"));
        }

        if latest_block_i64 == last_processed_block_id {
            trace!("Up-to-date with RPC, sleeping 5s");
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let start_block: u64 = (last_processed_block_id + 1).saturating_to();
        let end_block = min(start_block + range_size - 1, latest_block);
        info!(start_block, end_block, "Fetching new block range");

        let block_logs = rpc_client
            .fetch_logs_and_group_by_block(start_block, end_block)
            .await
            .context("Failed to fetch logs from RPC")?;
        info!(start_block, end_block, "Processing block range");

        for (block_number, logs) in block_logs.iter() {
            debug!(
                block_number,
                logs_count = logs.len(),
                "Processing block logs"
            );

            let records = rpc_client
                .process_logs_in_block(*block_number, logs, &mut active_job_ids)
                .context("Failed to process logs in block")?;

            Retry::spawn(retry_strategy.clone(), || async {
                let mut tx = repo.pool.begin().await?;
                let inserted_batch = repo.insert_events(&mut tx, records.clone()).await?;
                debug!(block_number, inserted_batch, "Inserted block logs");
                let updated = repo
                    .update_state(&mut tx, (*block_number).saturating_to())
                    .await?;
                trace!("Last processed block updated: {}", updated == 1);
                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("DB insert failed for block batch")?;
        }

        last_processed_block_id = end_block.saturating_to();
    }
}
