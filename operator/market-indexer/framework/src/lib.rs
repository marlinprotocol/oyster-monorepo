pub mod chain;
pub mod events;
pub(crate) mod repository;
pub(crate) mod schema;

use std::cmp::min;
use std::collections::HashSet;
use std::mem::take;
use std::pin::pin;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::time::{interval, sleep};
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, warn};

use chain::{ChainHandler, transform_block_logs_into_records};
use repository::Repository;

use crate::schema::JobEventRecord;

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
const BLOCK_THRESHOLD: i64 = 20;
const TIME_THRESHOLD_SECS: u64 = 5;

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
        last_processed_block_id = run_once(
            &repo,
            &rpc_client,
            &provider,
            last_processed_block_id,
            range_size,
            &mut active_job_ids,
        )
        .await?;

        sleep(Duration::from_secs(10)).await;
    }
}

async fn run_once(
    repo: &Repository,
    rpc_client: &impl ChainHandler,
    provider: &str,
    mut last_processed_block: i64,
    range_size: u64,
    active_jobs: &mut HashSet<String>,
) -> Result<i64> {
    info!("Starting new iteration to fetch and store logs");

    let mut block_logs_stream = match rpc_client.subscribe_logs_grouped_by_block().await {
        Ok(stream) => pin!(stream),
        Err(err) => {
            error!(error = ?err, "Failed to subscribe to logs on chain using RPC, retrying after 10s");
            return Ok(last_processed_block);
        }
    };
    info!("Subscribed to logs on chain!");

    let latest_block = match rpc_client.fetch_latest_block().await {
        Ok(block) => block,
        Err(err) => {
            error!(error = ?err, "Failed to fetch latest block from RPC, retrying after 10s");
            return Ok(last_processed_block);
        }
    };
    let latest_block_i64: i64 = latest_block.saturating_to();

    info!(latest_block, "Fetched latest block from RPC");

    if latest_block_i64 < last_processed_block {
        warn!(
            db_block = last_processed_block,
            rpc_block = latest_block_i64,
            "RPC is behind DB (possible rollback), waiting 10s before retrying"
        );
        return Ok(last_processed_block);
    }

    if latest_block_i64 > last_processed_block {
        let mut start_block: u64 = (last_processed_block + 1).saturating_to();
        while start_block <= latest_block {
            let end_block = min(start_block + range_size - 1, latest_block);
            info!(
                from = start_block,
                to = end_block,
                "Fetching new block range"
            );

            let block_logs = match rpc_client
                .fetch_logs_grouped_by_block(start_block, end_block)
                .await
            {
                Ok(logs) => logs,
                Err(err) => {
                    error!(from = start_block,
                        to = end_block,
                        error = ?err,
                        "Failed to fetch block logs from RPC, retrying after 10s"
                    );
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            info!(
                from = start_block,
                to = end_block,
                "Processing logs in block range"
            );

            let mut end_block_num = last_processed_block;
            let mut batch_records = Vec::new();

            for block_number in start_block..=end_block {
                let empty = Vec::new();

                let records = transform_block_logs_into_records(
                    provider,
                    block_logs.get(&block_number).unwrap_or(&empty),
                    active_jobs,
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
                    flush_batch(repo, batch, end_block_num).await?;

                    last_processed_block = end_block_num;
                }
            }

            if end_block_num > last_processed_block {
                let batch = take(&mut batch_records);
                flush_batch(repo, batch, end_block_num).await?;

                last_processed_block = end_block_num;
            }

            start_block = (last_processed_block + 1).saturating_to();
        }
    }

    let mut end_block_num = last_processed_block;
    let mut batch_records = Vec::new();
    let mut ticker = interval(Duration::from_secs(TIME_THRESHOLD_SECS));

    loop {
        tokio::select! {
            block_log = block_logs_stream.next() => {
                match block_log {
                    Some((block, logs)) => {
                        if block <= end_block_num.saturating_to() {
                            continue;
                        }

                        info!(block = block, logs_count = logs.len(), "Processing logs in block");

                        let records = transform_block_logs_into_records(provider, &logs, active_jobs)
                            .context(format!(
                                "Failed to transform block {} logs into DB records",
                                block
                            ))?;

                        info!(
                            block,
                            events_count = records.len(),
                            "Transformed block logs into records"
                        );

                        end_block_num = block.saturating_to();
                        batch_records.extend(records);

                        if batch_records.len() >= BATCH_THRESHOLD
                        || (end_block_num - last_processed_block) >= BLOCK_THRESHOLD
                        {
                            let batch = take(&mut batch_records);
                            flush_batch(repo, batch, end_block_num).await?;

                            last_processed_block = end_block_num;
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                let batch = take(&mut batch_records);
                if end_block_num > last_processed_block {
                    flush_batch(repo, batch, end_block_num).await?;

                    last_processed_block = end_block_num;
                }
            }
        }
    }

    Ok(last_processed_block)
}

async fn flush_batch(
    repo: &Repository,
    batch_records: Vec<JobEventRecord>,
    block: i64,
) -> Result<()> {
    let retry_strategy = ExponentialBackoff::from_millis(500)
        .max_delay(Duration::from_secs(10))
        .map(jitter)
        .take(3);

    Retry::spawn(retry_strategy, || async {
        let (inserted_batch, updated) = repo
            .insert_batch(&batch_records, block)
            .await
            .inspect_err(|err| {
                warn!(error = ?err, "Retrying insert_batch");
            })?;

        info!(
            current_block = block,
            batch_count = inserted_batch,
            "Inserted block logs to DB"
        );
        debug!("Last processed block updated: {}", updated == 1);

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context(format!(
        "DB insert failed for block logs up to {} after retries",
        block
    ))
}
