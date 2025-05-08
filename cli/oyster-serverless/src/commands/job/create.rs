use crate::commands::job::types::{CreateJobArgs, Relay, USDC};
use crate::configs::global::{RELAY_CONTRACT_ADDRESS, USDC_ADDRESS};
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

/// Creates a new job
pub async fn create_job(args: CreateJobArgs) -> Result<()> {
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

    // Parse addresses
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let callback_contract: Address = args.callback_contract_address.parse()?;

    // Get refund account - either the provided one or the sender's address
    let refund_account: Address = match args.refund_account {
        Some(addr) => addr.parse()?,
        None => signer_address,
    };

    // Create contract instance
    let contract = Relay::new(contract_address, provider.clone());

    // Parse code hash from hex to bytes32
    let code_hash_str = args.code_hash.strip_prefix("0x").unwrap_or(&args.code_hash);
    let decoded = hex::decode(code_hash_str).context("Failed to decode code hash hex string")?;
    let code_hash: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Code hash must be exactly 32 bytes"))?;
    let code_hash = FixedBytes::from(code_hash);

    // Convert numeric values to U256
    let user_timeout = U256::from(args.user_timeout);

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
    let execution_fee_per_ms = contract
        .getJobExecutionFeePerMs(args.env)
        .call()
        .await
        .context("Failed to get execution fee per ms")?;

    let gateway_fee_per_job = contract
        .GATEWAY_FEE_PER_JOB()
        .call()
        .await
        .context("Failed to get gateway fee per job")?;

    let fixed_gas = contract
        .FIXED_GAS()
        .call()
        .await
        .context("Failed to get fixed gas")?;

    let callback_measure_gas = contract
        .CALLBACK_MEASURE_GAS()
        .call()
        .await
        .context("Failed to get callback measure gas")?;

    let callback_deposit =
        max_gas_price * (callback_gas_limit + fixed_gas._0 + callback_measure_gas._0);

    let wallet_eth_balance = provider
        .get_balance(signer_address)
        .await
        .context("Failed to get wallet balance")?;

    if wallet_eth_balance < callback_deposit {
        error!(
            "Insufficient ETH balance. Required: {} ETH, Available: {} ETH",
            callback_deposit, wallet_eth_balance
        );
        return Ok(());
    }

    let usdc_required = execution_fee_per_ms._0 * user_timeout + gateway_fee_per_job._0;

    let usdc_contract = USDC::new(USDC_ADDRESS.parse()?, &provider);

    let usdc_balance = usdc_contract.balanceOf(signer_address).call().await?._0;

    if usdc_balance < usdc_required {
        error!(
            "Insufficient USDC balance. Required: {} USDC, Available: {} USDC",
            usdc_required, usdc_balance
        );
        return Ok(());
    }

    let prompt_message = format!(
        "The required deposits are {} USDC for the job and {} ETH for the callback deposit. Would you like to continue?",
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
    approve_usdc(usdc_required, provider, contract_address)
        .await
        .context("Failed to approve required USDC")?;

    // Call relayJob with all parameters
    info!("Submitting job to relay contract...");
    let tx = contract
        .relayJob(
            args.env,
            code_hash,
            code_inputs.into(),
            user_timeout,
            max_gas_price,
            refund_account,
            callback_contract,
            callback_gas_limit,
        )
        .value(callback_deposit)
        .send()
        .await?;

    let receipt = tx.get_receipt().await?;

    let data = receipt.inner.logs()[1].log_decode::<Relay::JobRelayed>()?;
    let job_id = data.data().jobId;

    info!("Job ID: {:?}", job_id);

    info!(
        "Job submitted successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}
