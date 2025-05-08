use crate::commands::subscription::types::{
    CreateSubscriptionArgs, RelayContract, RelaySubscriptions, USDC,
};
use crate::commands::subscription::utils::{
    get_periodic_gap, get_start_timestamp, get_termination_timestamp,
};
use crate::configs::global::{
    RELAY_CONTRACT_ADDRESS, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS, USDC_ADDRESS,
};
use crate::utils::conversion::{to_eth, to_usdc};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::hex;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, WalletProvider};
use anyhow::{Context, Result};
use inquire::Select;
use tokio::fs;
use tracing::{error, info};
use RelaySubscriptions::JobSubscriptionParams;

/// Handles the creation of a new subscription
pub async fn create_subscription(args: CreateSubscriptionArgs) -> Result<()> {
    // Check if input file exists if provided
    if let Some(input_path) = &args.input_file {
        if !std::path::Path::new(input_path).exists() {
            anyhow::bail!("Input file '{}' not found", input_path);
        }
    }

    // Load input file contents - empty vec if no file provided
    let code_inputs = match &args.input_file {
        Some(path) => fs::read(path).await.context("Failed to read input file")?,
        None => Vec::new(),
    };

    // Load wallet private key
    let wallet_private_key = &args.wallet.load_required()?;

    // Create provider with wallet
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get the signer's address
    let wallet = provider.wallet();
    let signer_address = wallet.default_signer_address();

    let callback_contract: Address = args.callback_contract_address.parse()?;

    // Parse addresses
    let relay_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;

    // Parse addresses
    let relay_contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;

    // Get refund account - either the provided one or the sender's address
    let refund_account: Address = match args.refund_account {
        Some(addr) => addr.parse()?,
        None => signer_address,
    };

    // Parse code hash from hex to bytes32
    let code_hash_str = args.code_hash.strip_prefix("0x").unwrap_or(&args.code_hash);
    let decoded = hex::decode(code_hash_str).context("Failed to decode code hash hex string")?;
    let code_hash: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Code hash must be exactly 32 bytes"))?;
    let code_hash = FixedBytes::from(code_hash);

    // Create contract instances
    let relay_subscription_contract =
        RelaySubscriptions::new(relay_subscription_contract_address, provider.clone());
    let relay_contract = RelayContract::new(relay_contract_address, provider.clone());

    // Get current gas price and calculate max gas price
    let current_gas_price = U256::from(
        provider
            .get_gas_price()
            .await
            .context("Failed to get current gas price")?,
    );

    let max_gas_price = U256::from(
        (current_gas_price.to_string().parse::<f64>().unwrap() * args.max_gas_price).round() as u64,
    );

    let callback_gas_limit = U256::from(args.callback_gas_limit);

    // Get execution fee per ms for the environment
    let execution_fee_per_ms = relay_contract
        .getJobExecutionFeePerMs(args.env)
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

    // Get interactive input for start_timestamp if not provided
    let start_timestamp = get_start_timestamp(args.start_timestamp).await?;

    // Get interactive input for termination_timestamp if not provided
    let termination_timestamp =
        get_termination_timestamp(start_timestamp, args.termination_timestamp).await?;

    // Get interactive input for periodic_gap if not provided
    let periodic_gap = get_periodic_gap(args.periodic_gap).await?;

    let user_timeout = U256::from(args.user_timeout);

    // Calculate total runs based on provided or interactively gathered parameters
    let total_runs = ((termination_timestamp - start_timestamp) / periodic_gap) + U256::from(1);

    info!("Subscription start time: {}", start_timestamp);
    info!("Subscription end time: {}", termination_timestamp);
    info!("Subscription interval: {} seconds", periodic_gap);
    info!("Total subscription runs: {}", total_runs - U256::from(1));

    // Calculate the callback deposit amount
    let callback_deposit =
        max_gas_price * (callback_gas_limit + fixed_gas._0 + callback_measure_gas._0) * total_runs;

    // Check ETH balance
    let wallet_eth_balance = provider
        .get_balance(signer_address)
        .await
        .context("Failed to get wallet balance")?;

    if wallet_eth_balance < callback_deposit {
        error!(
            "Insufficient ETH balance. Required: {} ETH, Available: {} ETH",
            to_eth(callback_deposit)?,
            to_eth(wallet_eth_balance)?
        );
        return Ok(());
    }

    // Check USDC balance
    let usdc_contract = USDC::new(USDC_ADDRESS.parse()?, &provider);
    let usdc_balance = usdc_contract.balanceOf(signer_address).call().await?._0;

    let usdc_required =
        ((user_timeout * execution_fee_per_ms._0) + gateway_fee_per_job._0) * total_runs;

    if usdc_balance < usdc_required {
        error!(
            "Insufficient USDC balance. Required: {} USDC, Available: {} USDC",
            to_usdc(usdc_required)?,
            to_usdc(usdc_balance)?
        );
        return Ok(());
    }

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
    approve_usdc(usdc_required, provider, relay_subscription_contract_address)
        .await
        .context("Failed to approve required USDC")?;

    info!("Submitting subscription to relay subscription contract...");

    let job_subs_params = {
        JobSubscriptionParams {
            env: args.env,
            startTime: start_timestamp,
            maxGasPrice: max_gas_price,
            usdcDeposit: usdc_required,
            callbackGasLimit: callback_gas_limit,
            callbackContract: callback_contract,
            codehash: code_hash,
            codeInputs: code_inputs.into(),
            periodicGap: periodic_gap,
            terminationTimestamp: termination_timestamp,
            userTimeout: user_timeout,
            refundAccount: refund_account,
        }
    };

    let tx = relay_subscription_contract
        .startJobSubscription(job_subs_params)
        .value(callback_deposit)
        .send()
        .await?;

    let receipt = tx.get_receipt().await?;

    info!(
        "Job submitted successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}
