use std::cmp::min;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tracing::{debug, info, instrument};

use crate::arb_client::ArbHandler;
use crate::repository::Repository;

#[instrument(level = "info", skip_all, parent = None)]
pub async fn run(repo: Repository, mut rpc_client: impl ArbHandler, range_size: u64) -> Result<()> {
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
        // fetch latest block from the rpc
        let latest_block = rpc_client
            .latest_block_with_retries()
            .await
            .context("Failed to fetch latest block from the rpc")?;
        let latest_block_i64 = latest_block as i64;

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
        let start_block = (last_processed_block_id + 1) as u64;
        // cap block range using range_size
        // might need some babysitting during initial sync
        let end_block = min(start_block + range_size - 1, latest_block);

        info!(start_block, end_block, "fetching range");

        let logs = rpc_client
            .logs_with_retries(start_block, end_block)
            .await
            .context("Failed to fetch logs from the rpc")?;

        info!(start_block, end_block, "processing range");

        let block_logs = rpc_client.group_logs_by_block(logs);

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
                let updated = repo.update_state(&mut tx, *block_number as i64).await?;
                debug!("is_last_set: {}", updated == 1);
                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("Failed to batch insert logs for a block in the DB")?;
        }

        last_processed_block_id = end_block as i64;
    }
}
