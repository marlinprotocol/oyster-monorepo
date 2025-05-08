use crate::commands::subscription::types::{
    RelayContract, RelaySubscriptions, UpdateSubscriptionArgs,
};
use crate::configs::global::{RELAY_CONTRACT_ADDRESS, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS};
use crate::utils::conversion::{to_eth, to_usdc};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::primitives::U256;
use alloy::providers::Provider;
use anyhow::{Context, Result};
use inquire::Select;
use tracing::info;

/// Update an existing subscription
pub async fn update_subscription(args: UpdateSubscriptionArgs) -> Result<()> {
    let termination_timestamp = U256::from(args.termination_timestamp);

    // Load wallet private key
    let wallet_private_key = &args.wallet.load_required()?;

    // Create provider with wallet
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    //Fetch tx receipt
    let tx_receipt = provider
        .get_transaction_receipt(args.subscription_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    let data =
        tx_receipt.inner.logs()[0].log_decode::<RelaySubscriptions::JobSubscriptionStarted>()?;

    let subscription_id = data.data().jobSubsId;
    let start_time = data.data().startTime;
    let periodic_gap = data.data().periodicGap;
    let env = data.data().env;

    // Create contract instances
    let realy_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;
    let realy_subscription_contract =
        RelaySubscriptions::new(realy_subscription_contract_address, provider.clone());

    // Parse addresses
    let relay_contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;

    let relay_contract = RelayContract::new(relay_contract_address, provider.clone());

    let job_subscription_data = realy_subscription_contract
        .jobSubscriptions(subscription_id)
        .call()
        .await
        .context("Failed to fetch job subscription data")?;

    let old_termination_timestamp = job_subscription_data.terminationTimestamp;
    let user_timeout = job_subscription_data.userTimeout;
    let max_gas_price = job_subscription_data.job.maxGasPrice;
    let callback_gas_limit = job_subscription_data.job.callbackGasLimit;

    if termination_timestamp == old_termination_timestamp {
        info!("The new termination timestamp is the same as the old one. No update needed.");
        return Ok(());
    } else if termination_timestamp < old_termination_timestamp {
        info!("Updating the subscription termination timestamp...");
        let tx = realy_subscription_contract
            .updateJobSubsTerminationParams(subscription_id, termination_timestamp, U256::from(0))
            .send()
            .await?;

        let receipt = tx.get_receipt().await?;

        info!(
            "Job updated successfully in transaction: {:?}",
            receipt.transaction_hash
        );

        return Ok(());
    }

    // Get execution fee per ms for the environment
    let execution_fee_per_ms = relay_contract
        .getJobExecutionFeePerMs(env)
        .call()
        .await
        .context("Failed to get execution fee per ms")?;

    let gateway_fee_per_job = relay_contract
        .GATEWAY_FEE_PER_JOB()
        .call()
        .await
        .context("Failed to get gateway fee per job")?;

    // Get fixed gas values from the contract
    let fixed_gas = relay_contract
        .FIXED_GAS()
        .call()
        .await
        .context("Failed to get fixed gas")?;

    let callback_measure_gas = relay_contract
        .CALLBACK_MEASURE_GAS()
        .call()
        .await
        .context("Failed to get callback measure gas")?;

    let old_total_runs = ((old_termination_timestamp - start_time) / periodic_gap) + U256::from(1);
    let new_total_runs = ((termination_timestamp - start_time) / periodic_gap) + U256::from(1);

    let additional_runs = new_total_runs - old_total_runs;

    let usdc_required =
        ((user_timeout * execution_fee_per_ms._0) + gateway_fee_per_job._0) * additional_runs;

    // Calculate the callback deposit amount
    let callback_deposit = max_gas_price
        * (callback_gas_limit + fixed_gas._0 + callback_measure_gas._0)
        * additional_runs;

    info!("Additional Runs: {}", additional_runs);

    // Prompt user for confirmation
    let prompt_message = format!(
            "The required deposits are {} USDC for the subscription and {} ETH for the callback deposit. Would you like to continue?",
            to_usdc(usdc_required)?,
            to_eth(callback_deposit)?
        );

    let options = vec!["Yes", "No"];

    let answer = Select::new(&prompt_message, options)
        .prompt()
        .context("Failed to get user confirmation")?;

    if answer == "No" {
        info!("Operation cancelled by user!");
        return Ok(());
    }

    //Approve USDC to the relay contract
    approve_usdc(usdc_required, provider, realy_subscription_contract_address)
        .await
        .context("Failed to approve required USDC")?;

    info!("Updating the subscription termination timestamp...");
    let tx = realy_subscription_contract
        .updateJobSubsTerminationParams(subscription_id, termination_timestamp, usdc_required)
        .value(callback_deposit)
        .send()
        .await?;

    let receipt = tx.get_receipt().await?;

    info!(
        "Job updated successfully in transaction: {:?}",
        receipt.transaction_hash
    );
    Ok(())
}
