use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{keccak256, Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    transports::http::Http,
};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tracing::info;

const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";
const OYSTER_MARKET_ADDRESS: &str = "0x9d95D61eA056721E358BC49fE995caBF3B86A34B"; // Mainnet Contract Address
const USDC_ADDRESS: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"; // Mainnet USDC Address
const MIN_DEPOSIT_AMOUNT: u64 = 1; // Minimum 0.000001 USDC

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/token_abi.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn deposit_to_job(job_id: &str, amount: u64, wallet_private_key: &str) -> Result<()> {
    info!("Starting deposit...");

    // Input validation
    if amount < MIN_DEPOSIT_AMOUNT {
        return Err(anyhow!(
            "Amount must be at least {} (0.000001 USDC)",
            MIN_DEPOSIT_AMOUNT
        ));
    }

    // Convert amount to U256 with 6 decimals (USDC has 6 decimals)
    let amount_u256 = U256::from(amount);

    // Setup wallet and provider with signer
    let private_key = FixedBytes::<32>::from_slice(
        &hex::decode(wallet_private_key).context("Failed to decode private key")?,
    );
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Failed to create signer from private key")?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            ARBITRUM_ONE_RPC_URL
                .parse()
                .context("Failed to parse RPC URL")?,
        );

    // Create contract instance
    let market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse()
            .context("Failed to parse market address")?,
        provider.clone(),
    );

    // Check if job exists and get current balance
    let job = market
        .jobs(job_id.parse().context("Failed to parse job ID")?)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }
    info!(
        "Depositing: {:.6} USDC",
        amount_u256.to::<u128>() as f64 / 1e6
    );

    // First approve USDC transfer
    approve_usdc(amount_u256, provider.clone()).await?;

    // Call jobDeposit function
    let tx_hash = market
        .jobDeposit(
            job_id.parse().context("Failed to parse job ID")?,
            amount_u256,
        )
        .send()
        .await
        .context("Failed to send deposit transaction")?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Deposit transaction failed - check contract interaction"
        ));
    }

    // Calculate event signature hash
    let job_deposited_signature = "JobDeposited(bytes32,address,uint256)";
    let job_deposited_topic = keccak256(job_deposited_signature.as_bytes());

    // Look for JobDeposited event
    let mut found_event = false;
    for log in receipt.inner.logs().iter() {
        if log.topics()[0] == job_deposited_topic {
            found_event = true;
            info!("Deposit successful!");
            info!("Transaction hash: {:?}", tx_hash);
            break;
        }
    }

    if !found_event {
        return Err(anyhow!(
            "JobDeposited event not found in transaction receipt"
        ));
    }

    Ok(())
}

async fn approve_usdc(amount: U256, provider: impl Provider<Http<Client>, Ethereum>) -> Result<()> {
    let usdc_address: Address = USDC_ADDRESS
        .parse()
        .context("Failed to parse USDC address")?;
    let market_address: Address = OYSTER_MARKET_ADDRESS
        .parse()
        .context("Failed to parse market address")?;

    let usdc = USDC::new(usdc_address, provider);
    let tx_hash = usdc
        .approve(market_address, amount)
        .send()
        .await
        .context("Failed to send USDC approval transaction")?
        .watch()
        .await
        .context("Failed to get USDC approval transaction hash")?;

    info!("USDC approval transaction: {:?}", tx_hash);
    Ok(())
}
