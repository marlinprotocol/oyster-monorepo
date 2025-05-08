use crate::commands::subscription::types::{FetchResponseArgs, RelayContract, RelaySubscriptions};
use crate::commands::subscription::utils::get_current_timestamp;
use crate::configs::global::RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS;
use crate::configs::global::{ARBITRUM_ONE_RPC_URL, RELAY_CONTRACT_ADDRESS};
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::Http;
use anyhow::{Context, Result};
use reqwest::Client;
use tokio::fs;
use tracing::info;

use super::types::RelaySubscriptions::RelaySubscriptionsInstance;

/// Fetches and processes subscription events
async fn fetch_and_process_subscription_events(
    subscription_contract: &RelaySubscriptionsInstance<
        Http<Client>,
        impl Provider<Http<Client>> + Clone,
    >,
    subscription_id: U256,
    from_block: u64,
    to_block: u64,
) -> Result<()> {
    let events = subscription_contract
        .JobSubscriptionResponded_filter()
        .from_block(from_block)
        .to_block(to_block)
        .topic1(subscription_id)
        .query()
        .await?;

    for event in events {
        let current_run = event.0.currentRuns;
        let output = event.0.output;
        info!("Received response for run {}", current_run);
        let file_name = format!("output_{}", current_run);
        let output_path = std::env::current_dir()?.join(file_name);
        fs::write(&output_path, output)
            .await
            .context("Failed to write response to output file")?;

        info!("Response saved to: {}", output_path.display());
    }

    Ok(())
}

/// Fetches responses for a subscription
pub async fn fetch_response(args: FetchResponseArgs) -> Result<()> {
    // Create provider with no wallet (read-only)
    let rpc_url = ARBITRUM_ONE_RPC_URL
        .parse()
        .context("Failed to parse RPC URL")?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    //Fetch tx receipt
    let tx_receipt = provider
        .get_transaction_receipt(args.subscription_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    //Fetch subscription ID and tx block number from the transaction receipt
    let tx_block_number = tx_receipt
        .block_number
        .context("Transaction receipt does not have a block number")?;

    let data =
        tx_receipt.inner.logs()[0].log_decode::<RelaySubscriptions::JobSubscriptionStarted>()?;
    let subscription_id = data.data().jobSubsId;
    let start_time = data.data().startTime;
    let periodic_gap = data.data().periodicGap;
    let termination_timestamp = data.data().terminationTimestamp;
    let total_runs = ((termination_timestamp - start_time) / periodic_gap) + U256::from(1);
    info!("Total Runs: {}", total_runs);

    info!(
        "Fetching subscription response for subscription ID: {:?}",
        subscription_id
    );

    // Create contract instances
    let realy_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;
    let realy_subscription_contract =
        RelaySubscriptions::new(realy_subscription_contract_address, provider.clone());

    let relay_contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let relay_contract = RelayContract::new(relay_contract_address, provider.clone());

    let overall_timeout = relay_contract
        .OVERALL_TIMEOUT()
        .call()
        .await
        .context("Failed to fetch overall timeout")?;

    let expiry_timestamp = termination_timestamp + overall_timeout._0;

    let current_timestamp = U256::from(get_current_timestamp());

    // Get JobSubscriptionResponded events filtered by subscription ID
    info!("Searching for subscription response...");

    if args.stream {
        // Stream mode: continuously poll for new events
        let mut last_processed_block = tx_block_number;

        // Poll for new events
        loop {
            let latest_block = provider.get_block_number().await?;

            fetch_and_process_subscription_events(
                &realy_subscription_contract,
                subscription_id,
                last_processed_block + 1,
                latest_block,
            )
            .await?;

            last_processed_block = latest_block;

            if current_timestamp >= expiry_timestamp {
                info!("Past the expiry timestamp. Stopping the stream.");
                return Ok(());
            }

            // Sleep for a shorter duration since we're tracking blocks explicitly
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    } else {
        // Non-stream mode: fetch all existing responses at once
        info!("Fetching all existing responses...");

        let latest_block = provider.get_block_number().await?;

        fetch_and_process_subscription_events(
            &realy_subscription_contract,
            subscription_id,
            tx_block_number,
            latest_block,
        )
        .await?;

        Ok(())
    }
}
