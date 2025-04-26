use crate::args::wallet::WalletArgs;
use crate::configs::global::OYSTER_SERVERLESS_CODE_CONTRACT_ADDRESS;
use crate::utils::provider::create_provider;
use alloy::sol;
use anyhow::{Context, Result};
use clap::Args;
use minify_js::{minify, Session, TopLevelMode};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterServerlessCodeContract,
    "src/abis/OysterServerlessCodeContract.json"
);

#[derive(Args)]
pub struct DeployArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Contract address to deploy to (optional, uses default if not specified)
    #[clap(short, long)]
    contract_address: Option<String>,

    /// Whether to minify the code before deployment
    #[clap(long)]
    minified: bool,
}

pub async fn run_deploy(args: DeployArgs) -> Result<()> {
    // Check if worker.js exists in current directory
    let worker_path = std::env::current_dir()?.join("worker.js");
    if !worker_path.exists() {
        anyhow::bail!("worker.js not found in current directory");
    }

    // Read worker.js content
    let worker_code = tokio::fs::read_to_string(&worker_path)
        .await
        .context("Failed to read worker.js")?;

    let final_code = if args.minified {
        info!("Minifying worker code...");
        // Minify the JS code
        let session = Session::new();
        let mut output = Vec::new();
        minify(
            &session,
            TopLevelMode::Global,
            worker_code.as_bytes(),
            &mut output,
        )
        .map_err(|e| anyhow::anyhow!("Failed to minify JS code: {}", e))?;

        String::from_utf8(output).context("Failed to convert minified code to string")?
    } else {
        info!("Skipping minification");
        worker_code
    };

    // Load wallet private key
    let wallet_private_key = &args.wallet.load_required()?;

    // Create provider with wallet
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get contract address (use default if not specified)
    let contract_address = match args.contract_address {
        Some(addr) => addr.parse()?,
        None => OYSTER_SERVERLESS_CODE_CONTRACT_ADDRESS.parse()?,
    };
    info!("Using contract address: {}", contract_address);

    // Create contract instance
    let contract = OysterServerlessCodeContract::new(contract_address, provider);
    info!("Deploying code to contract...");

    // Call saveCodeInCallData with code
    let tx = contract
        .saveCodeInCallData(final_code)
        .send()
        .await
        .context("Failed to send transaction")?;

    let receipt = tx.get_receipt().await?;

    info!(
        "Transaction sent to arbitrum one: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}
