pub mod chain;
pub mod events;
pub(crate) mod repository;
pub(crate) mod schema;

use std::cmp::min;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::time::sleep;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::{debug, info, instrument, trace};

use chain::{ChainHandler, transform_block_logs_into_records};
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
        if self < 0 { 0 } else { self as u64 }
    }
}

const BATCH_THRESHOLD: usize = 100;

// TODO: add custom errors
#[instrument(level = "info", skip_all, parent = None)]
pub async fn run(
    db_url: String,
    rpc_client: impl ChainHandler,
    provider: String,
    start_block: Option<i64>,
    range_size: u64,
) -> Result<()> {
    let repo = Repository::new(db_url)
        .await
        .context("Failed to initialize the Repository from the provided URL")?;

    info!("Applying pending migrations");
    repo.apply_migrations()
        .await
        .context("Failed to apply pending migrations to the DB")?;
    info!("Migrations applied");

    if let Some(start_block) = start_block {
        let updated = repo
            .update_state_atomic(start_block)
            .await
            .context("Failed to update start block in the DB")?;

        debug!("Start block updated: {}", updated == 1);
    }

    let chain_id = rpc_client
        .fetch_chain_id()
        .await
        .context("RPC chain ID fetch failed")?;

    let updated = repo
        .update_chain_id(chain_id)
        .await
        .context("Failed to update chain ID in the DB")?;

    debug!("Chain ID updated: {}", updated == 1);

    if range_size == 0 {
        return Err(anyhow!("Range size must not be zero"));
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
    .context("Failed to fetch active job IDs from the DB")?;

    loop {
        let latest_block = rpc_client
            .fetch_latest_block()
            .await
            .context("RPC latest block fetch failed")?;
        let latest_block_i64: i64 = latest_block.saturating_to();

        debug!(latest_block, "Fetched latest block from RPC");

        if latest_block_i64 < last_processed_block_id {
            // warn!(db_block = last_processed_block_id, rpc_block = latest_block_i64, "RPC is behind DB (possible rollback)");
            return Err(anyhow!(
                "RPC {} is behind DB {} (possible rollback)",
                latest_block_i64,
                last_processed_block_id
            ));
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
            .context("Failed to fetch logs from the chain")?;
        info!(start_block, end_block, "Processing block range");

        let mut end_block_num = last_processed_block_id;
        let mut batch_records = Vec::new();

        for block_number in start_block..=end_block {
            let empty = Vec::new();

            let records = transform_block_logs_into_records(
                &provider,
                block_logs.get(&block_number).unwrap_or(&empty),
                &mut active_job_ids,
            )
            .context("Failed to transform block logs into DB records")?;

            debug!(
                block_number,
                events_count = records.len(),
                "Processing block logs"
            );

            end_block_num = block_number.saturating_to();
            batch_records.extend(records);

            if batch_records.len() >= BATCH_THRESHOLD {
                Retry::spawn(retry_strategy.clone(), || async {
                    let (inserted_batch, updated) = repo
                        .insert_batch(batch_records.clone(), end_block_num)
                        .await?;

                    debug!(end_block_num, inserted_batch, "Inserted block logs");
                    trace!("Last processed block updated: {}", updated == 1);

                    Ok::<(), anyhow::Error>(())
                })
                .await
                .context("DB insert failed for block batch")?;

                batch_records.clear();
                last_processed_block_id = end_block_num;
            }
        }

        if end_block_num > last_processed_block_id {
            Retry::spawn(retry_strategy.clone(), || async {
                let (inserted_batch, updated) = repo
                    .insert_batch(batch_records.clone(), end_block_num)
                    .await?;

                debug!(end_block_num, inserted_batch, "Inserted block logs");
                trace!("Last processed block updated: {}", updated == 1);

                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("DB insert failed for block batch")?;
        }

        last_processed_block_id = end_block_num;
    }
}
