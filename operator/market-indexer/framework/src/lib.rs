pub mod chain;
pub mod events;
pub(crate) mod repository;
pub(crate) mod schema;

use std::cmp::min;
use std::mem::take;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::time::sleep;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::{debug, error, info, instrument, warn};

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
    mut start_block: Option<i64>,
    range_size: u64,
) -> Result<()> {
    let repo = Repository::new(db_url)
        .await
        .context("Failed to initialize the Repository from the provided DB URL")?;

    info!("Applying pending migrations");
    repo.apply_migrations()
        .await
        .context("Failed to apply pending migrations to the DB")?;
    info!("Migrations applied");

    let retry_strategy = ExponentialBackoff::from_millis(500)
        .max_delay(Duration::from_secs(10))
        .take(3)
        .map(jitter);

    let mut last_processed_block_id = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_last_processed_block().await.inspect_err(|err| {
            warn!(error = ?err, "Retrying get_last_processed_block");
        })
    })
    .await
    .context("Missing last processed block (possible DB corruption)")?;

    if let Some(block) = start_block {
        if block <= last_processed_block_id {
            warn!(
                "Provided start block {} is behind the last processed block {}, starting from the later!",
                block, last_processed_block_id
            );
            start_block = None;
        } else {
            last_processed_block_id = block - 1;
        }
    }

    info!(
        last_processed_block_id,
        "Resuming from last processed block"
    );

    let chain_id = rpc_client
        .fetch_chain_id()
        .await
        .context("RPC chain ID fetch failed")?;

    let extra_decimals = rpc_client
        .fetch_extra_decimals()
        .await
        .context("Market EXTRA_DECIMALS fetch failed")?;

    let updated = Retry::spawn(retry_strategy.clone(), || async {
        repo.update_indexer_state(chain_id.clone(), extra_decimals, start_block)
            .await
            .inspect_err(|err| {
                warn!(error = ?err, "Retrying update_indexer_state");
            })
    })
    .await
    .context("Failed to update indexer state in the DB")?;

    info!("Indexer state updated: {}", updated == 1);

    if range_size == 0 {
        return Err(anyhow!("Range size must not be zero"));
    }

    let mut active_job_ids = Retry::spawn(retry_strategy.clone(), || async {
        repo.get_active_jobs().await.inspect_err(|err| {
            warn!(error = ?err, "Retrying get_active_jobs");
        })
    })
    .await
    .context("Failed to fetch active job IDs from the DB")?;

    loop {
        info!("Starting new iteration to fetch and store logs");

        let latest_block = match rpc_client.fetch_latest_block().await {
            Ok(block) => block,
            Err(err) => {
                error!(error = ?err, "Failed to fetch latest block from RPC, retrying after 10s");
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let latest_block_i64: i64 = latest_block.saturating_to();

        info!(latest_block, "Fetched latest block from RPC");

        if latest_block_i64 < last_processed_block_id {
            warn!(
                db_block = last_processed_block_id,
                rpc_block = latest_block_i64,
                "RPC is behind DB (possible rollback), waiting 10s before retrying"
            );
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        if latest_block_i64 == last_processed_block_id {
            debug!("Up-to-date with RPC, sleeping 5s");
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let start_block: u64 = (last_processed_block_id + 1).saturating_to();
        let end_block = min(start_block + range_size - 1, latest_block);
        info!(
            from = start_block,
            to = end_block,
            "Fetching new block range"
        );

        let block_logs = match rpc_client
            .fetch_logs_and_group_by_block(start_block, end_block)
            .await
        {
            Ok(logs) => logs,
            Err(err) => {
                error!(from = start_block, to = end_block, error = ?err, "Failed to fetch block logs from RPC, retrying after 10s");
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        info!(
            from = start_block,
            to = end_block,
            "Processing logs in block range"
        );

        let mut end_block_num = last_processed_block_id;
        let mut batch_records = Vec::new();

        for block_number in start_block..=end_block {
            let empty = Vec::new();

            let records = transform_block_logs_into_records(
                &provider,
                block_logs.get(&block_number).unwrap_or(&empty),
                &mut active_job_ids,
            )
            .context(format!(
                "Failed to transform block {} logs into DB records",
                block_number
            ))?;

            info!(
                block_number,
                events_count = records.len(),
                "Transformed block logs into records"
            );

            end_block_num = block_number.saturating_to();
            batch_records.extend(records);

            if batch_records.len() >= BATCH_THRESHOLD {
                let batch = take(&mut batch_records);

                Retry::spawn(retry_strategy.clone(), || {
                    let batch = batch.clone();
                    let repo = repo.clone();

                    async move {
                        let (inserted_batch, updated) = repo
                            .insert_batch(batch, end_block_num)
                            .await
                            .inspect_err(|err| {
                                warn!(error = ?err, "Retrying insert_batch");
                            })?;

                        info!(
                            current_block = end_block_num,
                            batch_count = inserted_batch,
                            "Inserted block logs to DB"
                        );
                        debug!("Last processed block updated: {}", updated == 1);

                        Ok::<(), anyhow::Error>(())
                    }
                })
                .await
                .context(format!(
                    "DB insert failed for block logs up to {} after retries",
                    end_block_num
                ))?;

                batch_records.clear();
                last_processed_block_id = end_block_num;
            }
        }

        if end_block_num > last_processed_block_id {
            let batch = take(&mut batch_records);

            Retry::spawn(retry_strategy.clone(), || {
                let batch = batch.clone();
                let repo = repo.clone();

                async move {
                    let (inserted_batch, updated) = repo
                        .insert_batch(batch, end_block_num)
                        .await
                        .inspect_err(|err| {
                        warn!(error = ?err, "Retrying insert_batch");
                    })?;

                    info!(
                        current_block = end_block_num,
                        batch_count = inserted_batch,
                        "Inserted block logs to DB"
                    );
                    debug!("Last processed block updated: {}", updated == 1);

                    Ok::<(), anyhow::Error>(())
                }
            })
            .await
            .context(format!(
                "DB insert failed for final batch in the range (blocks up to {})",
                end_block_num
            ))?;
        }

        last_processed_block_id = end_block_num;
    }
}
