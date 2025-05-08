use crate::commands::job::types::{FetchResponseArgs, Relay};
use crate::configs::global::ARBITRUM_ONE_RPC_URL;
use crate::configs::global::RELAY_CONTRACT_ADDRESS;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use tokio::fs;
use tracing::{error, info};

/// Fetches response for a job
pub async fn fetch_response(args: FetchResponseArgs) -> Result<()> {
    // Create provider with no wallet (read-only)
    let rpc_url = ARBITRUM_ONE_RPC_URL
        .parse()
        .context("Failed to parse RPC URL")?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    //Fetch tx receipt
    let tx_receipt = provider
        .get_transaction_receipt(args.job_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    //Fetch job ID and tx block number from the transaction receipt
    let tx_block_number = tx_receipt
        .block_number
        .context("Transaction receipt does not have a block number")?;

    let data = tx_receipt.inner.logs()[1].log_decode::<Relay::JobRelayed>()?;
    let job_id = data.data().jobId;

    // Create contract instance
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let contract = Relay::new(contract_address, provider.clone());

    info!("Fetching job response for job ID: {:?}", job_id);

    // Get JobResponded events filtered by job ID
    info!("Searching for job response...");

    let log = contract
        .JobResponded_filter()
        .from_block(tx_block_number)
        .topic1(job_id);

    let events = log.query().await?;

    if events.is_empty() {
        error!("No response found for job ID: {:?}", job_id);
        return Ok(());
    }

    let job_output = &events[0].0.output;

    info!("Job response found!");

    let output_path = std::env::current_dir()?.join("output");
    fs::write(&output_path, job_output)
        .await
        .context("Failed to write response to output file")?;

    info!("Response saved to: {}", output_path.display());

    Ok(())
}
