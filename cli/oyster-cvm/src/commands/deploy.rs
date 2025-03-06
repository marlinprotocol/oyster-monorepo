use crate::commands::log::stream_logs;
use crate::configs::global::{CREDIT_MANAGER_ADDRESS, OYSTER_MARKET_ADDRESS};
use crate::utils::credit::{approve_credit, get_credit_balance};
use crate::utils::{
    bandwidth::{calculate_bandwidth_cost, get_bandwidth_rate_for_region},
    provider::{create_provider, OysterProvider},
    usdc::{approve_usdc, format_usdc},
};
use alloy::{
    primitives::{keccak256, Address, B256 as H256, U256},
    providers::Provider,
    sol,
};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::Duration as StdDuration;
use tokio::net::TcpStream;
use tracing::info;

// Retry Configuration
const IP_CHECK_RETRIES: u32 = 20;
const IP_CHECK_INTERVAL: u64 = 15;
const ATTESTATION_RETRIES: u32 = 20;
const ATTESTATION_INTERVAL: u64 = 15;
const TCP_CHECK_RETRIES: u32 = 20;
const TCP_CHECK_INTERVAL: u64 = 15;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CreditManager,
    "src/abis/credit_manager_abi.json"
);
#[derive(Debug)]
pub struct DeploymentConfig {
    pub image_url: String,
    pub region: String,
    pub instance_type: String,
    pub bandwidth: u32,
    pub duration: u32,
    pub job_name: String,
    pub debug: bool,
    pub no_stream: bool,
    pub init_params: String,
    pub extra_init_params: String,
}

#[derive(Serialize, Deserialize)]
struct Operator {
    allowed_regions: Vec<String>,
    min_rates: Vec<RateCard>,
}

#[derive(Serialize, Deserialize)]
struct RateCard {
    region: String,
    rate_cards: Vec<InstanceRate>,
}

#[derive(Serialize, Deserialize, Clone)]
struct InstanceRate {
    instance: String,
    min_rate: String,
    cpu: u32,
    memory: u32,
    arch: String,
}

pub async fn deploy_oyster_instance(
    config: DeploymentConfig,
    wallet_private_key: &str,
    operator: &str,
) -> Result<()> {
    tracing::info!("Starting deployment...");

    // Setup provider
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get CP URL using the configured provider
    let cp_url = get_operator_cp(operator, provider.clone())
        .await
        .context("Failed to get CP URL")?;
    info!("CP URL for operator: {}", cp_url);

    // Fetch operator specs from CP URL
    let spec_url = format!("{}/spec", cp_url);
    let operator_spec = fetch_operator_spec(&spec_url)
        .await
        .context("Failed to fetch operator spec")?;

    // Validate region is supported
    if !operator_spec
        .allowed_regions
        .iter()
        .any(|r| r == &config.region)
    {
        return Err(anyhow!(
            "Region '{}' not supported by operator",
            config.region
        ));
    }

    // Fetch operator min rates with early validation
    let selected_instance =
        find_minimum_rate_instance(&operator_spec, &config.region, &config.instance_type)
            .context("Configuration not supported by operator")?;

    // Calculate costs
    let duration_seconds = (config.duration as u64) * 60;
    let (total_cost, total_rate) = calculate_total_cost(
        &selected_instance,
        duration_seconds,
        config.bandwidth,
        &config.region,
        &cp_url,
    )
    .await?;

    info!("Total cost: {:.6} USDC", format_usdc(total_cost));
    info!(
        "Total rate: {:.6} USDC/hour",
        (total_rate.to::<u128>() * 3600) as f64 / 1e18,
    );

    // Create metadata
    let metadata = create_metadata(
        &selected_instance.instance,
        &config.region,
        selected_instance.memory,
        selected_instance.cpu,
        &config.image_url,
        &config.job_name,
        config.debug,
        &config.init_params,
        &config.extra_init_params,
    );

    let credit_balance = match get_credit_balance(provider.clone()).await {
        Ok(balance) => balance,
        Err(_) => {
            return Err(anyhow!("Failed to get balance from Contract"));
        }
    };

    // Simplify payment logic - use min to determine credit amount and remainder for tokens
    let credit_amount = std::cmp::min(credit_balance, total_cost);
    let token_amount = total_cost - credit_amount;

    if credit_amount > U256::from(0) {
        info!("Using {} credits for payment", format_usdc(credit_amount));
        approve_credit(credit_amount, provider.clone()).await?;
    }
    if token_amount > U256::from(0) {
        info!("Using {} USDC for payment", format_usdc(token_amount));
        approve_usdc(token_amount, provider.clone()).await?;
    }

    // Create job
    let job_id = create_new_oyster_job(
        metadata,
        operator.parse()?,
        total_rate,
        credit_amount,
        token_amount,
        provider.clone(),
    )
    .await?;
    info!("Job created with ID: {:?}", job_id);

    info!("Waiting for 3 minutes for enclave to start...");
    tokio::time::sleep(StdDuration::from_secs(180)).await;

    let ip_address = wait_for_ip_address(&cp_url, job_id, &config.region).await?;
    info!("IP address obtained: {}", ip_address);

    if !check_reachability(&ip_address).await {
        return Err(anyhow!("Reachability check failed after maximum retries"));
    }

    info!("Enclave is ready! IP address: {}", ip_address);

    if config.debug && !config.no_stream {
        info!("Debug mode enabled - starting log streaming...");
        stream_logs(&ip_address, Some("0"), true, false).await?;
    }

    Ok(())
}

async fn create_new_oyster_job(
    metadata: String,
    provider_addr: Address,
    rate: U256,
    credit_amount: U256,
    token_amount: U256,
    provider: OysterProvider,
) -> Result<H256> {
    let tx_hash;
    let credit_manager_address = CREDIT_MANAGER_ADDRESS.parse::<Address>()?;

    // Load CreditManager contract using Alloy
    let provider_clone = provider.clone();
    let credit_manager = CreditManager::new(credit_manager_address, provider_clone);

    tx_hash = credit_manager
        .jobOpen(metadata, provider_addr, rate, credit_amount, token_amount)
        .send()
        .await?
        .watch()
        .await?;

    info!("Job creation transaction: {:?}", tx_hash);

    let job_id = get_receipt_and_job_id(tx_hash, provider).await?;

    Ok(job_id)
}

async fn get_receipt_and_job_id(tx_hash: H256, provider: OysterProvider) -> Result<H256> {
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    // Add logging to check transaction status
    if !receipt.status() {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    let credit_manager_job_opened_signature = "JobOpened(bytes32,address,uint256,uint256)";
    let credit_manager_job_opened_topic = keccak256(credit_manager_job_opened_signature.as_bytes());

    // Look for JobOpened event
    for log in receipt.inner.logs().iter() {
        if log.topics()[0] == credit_manager_job_opened_topic {
            info!("Found JobOpened event");
            return Ok(log.topics()[1]);
        }
    }

    // If we can't find the JobOpened event
    info!("No JobOpened event found. All topics:");
    for log in receipt.inner.logs().iter() {
        info!("Event topics: {:?}", log.topics());
    }

    Err(anyhow!(
        "Could not find JobOpened event in transaction receipt"
    ))
}

async fn fetch_operator_spec(url: &str) -> Result<Operator> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let operator: Operator = response.json().await?;
    Ok(operator)
}

async fn wait_for_ip_address(url: &str, job_id: H256, region: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let mut last_response = String::new();

    // Construct the IP endpoint URL with query parameters
    let ip_url = format!("{}/ip?id={:?}&region={}", url, job_id, region);

    for attempt in 1..=IP_CHECK_RETRIES {
        info!(
            "Checking for IP address (attempt {}/{})",
            attempt, IP_CHECK_RETRIES
        );

        let response = client.get(&ip_url).send().await?;
        let json: serde_json::Value = response.json().await?;
        last_response = json.to_string();

        info!("Response from IP endpoint: {}", last_response);

        // Check for IP in response
        if let Some(ip) = json.get("ip").and_then(|ip| ip.as_str()) {
            if !ip.is_empty() {
                return Ok(ip.to_string());
            }
        }

        info!("IP not found yet, waiting {} seconds...", IP_CHECK_INTERVAL);
        tokio::time::sleep(StdDuration::from_secs(IP_CHECK_INTERVAL)).await;
    }

    Err(anyhow!(
        "IP address not found after {} attempts. Last response: {}",
        IP_CHECK_RETRIES,
        last_response
    ))
}

async fn ping_ip(ip: &str) -> bool {
    let address = format!("{}:1300", ip);
    for attempt in 1..=TCP_CHECK_RETRIES {
        info!(
            "Attempting TCP connection to {} (attempt {}/{})",
            address, attempt, TCP_CHECK_RETRIES
        );
        match tokio::time::timeout(StdDuration::from_secs(2), TcpStream::connect(&address)).await {
            Ok(Ok(_)) => {
                return true;
            }
            Ok(Err(e)) => info!("TCP connection failed: {}", e),
            Err(_) => info!("TCP connection timed out"),
        }
        tokio::time::sleep(StdDuration::from_secs(TCP_CHECK_INTERVAL)).await;
    }
    info!("All TCP connection attempts failed");
    false
}

async fn check_reachability(ip: &str) -> bool {
    // First check basic connectivity
    if !ping_ip(ip).await {
        tracing::error!("Failed to establish TCP connection to the instance");
        return false;
    }

    let client = reqwest::Client::new();
    let attestation_url = format!("http://{}:1300/attestation/raw", ip);

    for attempt in 1..=ATTESTATION_RETRIES {
        info!(
            "Checking reachability (attempt {}/{})",
            attempt, ATTESTATION_RETRIES
        );

        match client.get(&attestation_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => {
                            info!("Reachability check successful");
                            return true;
                        }
                        Ok(_) => info!("Empty attestation response"),
                        Err(e) => info!("Error reading attestation response: {}", e),
                    }
                }
            }
            Err(e) => info!("Failed to connect to attestation endpoint: {}", e),
        }

        info!(
            "Waiting {} seconds before next reachability check...",
            ATTESTATION_INTERVAL
        );
        tokio::time::sleep(StdDuration::from_secs(ATTESTATION_INTERVAL)).await;
    }

    false
}

fn create_metadata(
    instance: &str,
    region: &str,
    memory: u32,
    vcpu: u32,
    url: &str,
    name: &str,
    debug: bool,
    init_params: &str,
    extra_init_params: &str,
) -> String {
    serde_json::json!({
        "instance": instance,
        "region": region,
        "memory": memory,
        "vcpu": vcpu,
        "url": url,
        "name": name,
        "family": "tuna",
        "debug": debug,
        "init_params": init_params,
        "extra_init_params": extra_init_params,
    })
    .to_string()
}

fn find_minimum_rate_instance(
    operator: &Operator,
    region: &str,
    instance: &str,
) -> Result<InstanceRate> {
    operator
        .min_rates
        .iter()
        .find(|rate_card| rate_card.region == region)
        .ok_or_else(|| anyhow!("No rate card found for region: {}", region))?
        .rate_cards
        .iter()
        .filter(|rate| rate.instance == instance)
        .min_by(|a, b| {
            let a_rate =
                U256::from_str_radix(a.min_rate.trim_start_matches("0x"), 16).unwrap_or(U256::MAX);
            let b_rate =
                U256::from_str_radix(b.min_rate.trim_start_matches("0x"), 16).unwrap_or(U256::MAX);
            a_rate.cmp(&b_rate)
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "No matching instance rate found for region: {}, instance: {}",
                region,
                instance
            )
        })
}

async fn calculate_total_cost(
    instance_rate: &InstanceRate,
    duration: u64,
    bandwidth: u32,
    region: &str,
    cp_url: &str,
) -> Result<(U256, U256)> {
    let instance_secondly_rate_usdc =
        U256::from_str_radix(instance_rate.min_rate.trim_start_matches("0x"), 16)?;

    let instance_cost_scaled = U256::from(duration)
        .checked_mul(instance_secondly_rate_usdc)
        .context("Failed to multiply duration and instance rate")?;

    let bandwidth_rate_region = get_bandwidth_rate_for_region(region, cp_url).await?;
    let bandwidth_cost_scaled = U256::from(
        calculate_bandwidth_cost(
            &bandwidth.to_string(),
            "KBps",
            bandwidth_rate_region,
            duration,
        )
        .context("Failed to calculate bandwidth cost")?,
    );

    let bandwidth_rate_scaled = bandwidth_cost_scaled
        .checked_div(U256::from(duration))
        .context("Failed to divide bandwidth cost by duration")?;
    let total_cost_scaled = (instance_cost_scaled
        .checked_add(bandwidth_cost_scaled)
        .context("Failed to add instance and bandwidth costs")?
        .checked_div(U256::from(1e12)))
    .context("Failed to divide total cost by 1e12")?;
    let total_rate_scaled = instance_secondly_rate_usdc
        .checked_add(bandwidth_rate_scaled)
        .context("Failed to add instance and bandwidth rates")?;

    Ok((total_cost_scaled, total_rate_scaled))
}

async fn get_operator_cp(provider_address: &str, provider: OysterProvider) -> Result<String> {
    let market_address = Address::from_str(OYSTER_MARKET_ADDRESS)?;
    let provider_address = Address::from_str(provider_address)?;

    // Create contract instance
    let market = OysterMarket::new(market_address, provider);

    // Call providers function to get CP URL
    let cp_url = market.providers(provider_address).call().await?.cp;

    Ok(cp_url)
}
