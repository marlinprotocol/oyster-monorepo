use crate::{
    args::{init_params::InitParamsArgs, wallet::WalletArgs},
    commands::log::{stream_logs, LogArgs},
    configs::{
        blockchain::Blockchain,
        global::{OYSTER_MARKET_ADDRESS, SOLANA_USDC_MINT_ADDRESS},
    },
    types::Platform,
    utils::{
        bandwidth::{calculate_bandwidth_cost, get_bandwidth_rate_for_region},
        provider::{create_ethereum_provider, create_solana_provider},
        solana::create_all_associated_token_accounts,
        token::approve_total_cost,
        usdc::format_usdc,
    },
};
use alloy::{
    network::Ethereum,
    primitives::{keccak256, Address, B256 as H256, U256},
    providers::{Provider, WalletProvider},
    sol,
    transports::http::Http,
};
use anchor_client::{
    solana_sdk::{
        signature::{Keypair, Signature},
        system_program,
    },
    Client as AnchorClient,
};
use anchor_lang::{declare_program, prelude::Pubkey};
use anchor_spl::{associated_token::get_associated_token_address, token};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use solana_transaction_status_client_types::UiTransactionEncoding;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration as StdDuration;
use tokio::{net::TcpStream, time::sleep};
use tracing::{error, info};

declare_program!(market_v);
use market_v::{
    accounts::{Market as SolanaMarketVMarket, Provider as SolanaMarketVProvider},
    client::accounts::JobOpen as SolanaMarketVJobOpen,
    client::args::JobOpen as SolanaMarketVJobOpenArgs,
};

declare_program!(oyster_credits);

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

#[derive(Args, Debug, Clone)]
pub struct DeployArgs {
    /// Preset for parameters (e.g. blue)
    #[arg(long, default_value = "blue")]
    preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = Platform::ARM64.as_str())]
    arch: Platform,

    /// Select Blockchain
    #[arg(long, default_value = Blockchain::Arbitrum.as_str())]
    blockchain: Blockchain,

    #[command(flatten)]
    wallet: WalletArgs,

    /// Operator address
    #[arg(long, default_value = "0xe10fa12f580e660ecd593ea4119cebc90509d642")]
    operator: String,

    /// URL of the enclave image
    #[arg(long)]
    image_url: Option<String>,

    /// Region for deployment
    #[arg(long, default_value = "ap-south-1")]
    region: String,

    /// Instance type (e.g. "r6g.large")
    #[arg(long)]
    instance_type: Option<String>,

    /// Optional bandwidth in KBps (default: 10)
    #[arg(long, default_value = "10")]
    bandwidth: u32,

    /// Duration in minutes
    #[arg(long, required = true)]
    duration_in_minutes: u32,

    /// Job name
    #[arg(long, default_value = "")]
    job_name: String,

    /// Enable debug mode
    #[arg(long)]
    debug: bool,

    /// Disable automatic log streaming in debug mode
    #[arg(long, requires = "debug")]
    no_stream: bool,

    /// Init params
    #[command(flatten)]
    init_params: InitParamsArgs,
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

pub async fn deploy(args: DeployArgs) -> Result<()> {
    info!("Starting deployment...");

    let result: (String, H256);
    if args.blockchain == Blockchain::Arbitrum {
        result = deploy_to_arbitrum(&args).await?;
    } else if args.blockchain == Blockchain::Solana {
        result = deploy_to_solana(&args).await?;
    } else {
        return Err(anyhow!("Unsupported blockchain: {:?}", args.blockchain));
    }

    let cp_url = result.0;
    let job_id = result.1;

    info!("Waiting for 3 minutes for enclave to start...");
    tokio::time::sleep(StdDuration::from_secs(180)).await;

    let ip_address = wait_for_ip_address(&cp_url, job_id, &args.region).await?;
    info!("IP address obtained: {}", ip_address);

    if !check_reachability(&ip_address).await {
        return Err(anyhow!("Reachability check failed after maximum retries"));
    }

    info!("Enclave is ready! IP address: {}", ip_address);

    if args.debug && !&args.no_stream {
        info!("Debug mode enabled - starting log streaming...");
        stream_logs(LogArgs {
            ip: ip_address,
            start_from: Some("0".into()),
            with_log_id: true,
            quiet: false,
        })
        .await?;
    }

    Ok(())
}

async fn deploy_to_arbitrum(args: &DeployArgs) -> Result<(String, H256)> {
    let provider =
        create_ethereum_provider(&args.wallet.load_required()?, &args.blockchain).await?;

    // Get CP URL using the configured provider
    let cp_url = get_ethereum_operator_cp(&args.operator, provider.clone())
        .await
        .context("Failed to get CP URL")?;
    info!("CP URL for operator: {}", cp_url);

    let (metadata, total_cost, total_rate) = get_metadata_and_costs(&cp_url, args.clone()).await?;

    approve_total_cost(total_cost, provider.clone()).await?;

    // Create job
    let job_id = create_new_oyster_job_on_ethereum(
        metadata,
        args.operator.parse()?,
        total_rate,
        total_cost,
        provider.clone(),
    )
    .await?;
    info!("Job created with ID: {:?}", job_id);

    Ok((cp_url, job_id))
}

async fn deploy_to_solana(args: &DeployArgs) -> Result<(String, H256)> {
    let provider: AnchorClient<Rc<Keypair>> =
        create_solana_provider(&args.wallet.load_required()?, &args.blockchain).await?;

    let cp_url = get_solana_operator_cp(&args.operator, &provider)
        .await
        .context("Failed to get CP URL")?;
    info!("CP URL for operator: {}", cp_url);

    let (metadata, total_cost, total_rate) = get_metadata_and_costs(&cp_url, args.clone()).await?;

    let job_id = create_new_oyster_job_on_solana(
        metadata,
        args.operator.parse()?,
        total_rate,
        total_cost,
        &provider,
    )
    .await?;

    let job_id_u128 = U256::from_str(&job_id.to_string()).unwrap().to::<u128>();

    info!("Job created with ID: {:?}", job_id_u128);

    Ok((cp_url, job_id))
}

async fn get_metadata_and_costs(cp_url: &str, args: DeployArgs) -> Result<(String, U256, U256)> {
    // Fetch operator specs from CP URL
    let spec_url = format!("{}/spec", cp_url);
    let operator_spec = fetch_operator_spec(&spec_url)
        .await
        .context("Failed to fetch operator spec")?;

    // Validate region is supported
    if !operator_spec
        .allowed_regions
        .iter()
        .any(|r| r == &args.region)
    {
        return Err(anyhow!(
            "Region '{}' not supported by operator",
            args.region
        ));
    }

    let instance_type =
        args.instance_type
            .map(Result::Ok)
            .unwrap_or(match args.preset.as_str() {
                "blue" => match args.arch {
                    Platform::AMD64 => Ok("c6a.xlarge".into()),
                    Platform::ARM64 => Ok("c6g.large".into()),
                },
                _ => Err(anyhow!("Instance type is required")),
            })?;

    // Fetch operator min rates with early validation
    let selected_instance =
        find_minimum_rate_instance(&operator_spec, &args.region, &instance_type)
            .context("Configuration not supported by operator")?;

    // Calculate costs
    let duration_seconds = (args.duration_in_minutes as u64) * 60;
    let (total_cost, total_rate) = calculate_total_cost(
        &selected_instance,
        duration_seconds,
        args.bandwidth,
        &args.region,
        &cp_url,
    )
    .await?;

    info!("Total cost: {:.6} USDC", format_usdc(total_cost));
    info!(
        "Total rate: {:.6} USDC/hour",
        (total_rate.to::<u128>() * 3600) as f64 / 1e18,
    );

    let image_url = args
        .image_url
        .map(Result::Ok)
        .unwrap_or(match args.preset.as_str() {
            "blue" => match args.arch {
                Platform::AMD64 => Ok(
                    "https://artifacts.marlin.org/oyster/eifs/base-blue_v1.0.0_linux_amd64.eif"
                        .into(),
                ),
                Platform::ARM64 => Ok(
                    "https://artifacts.marlin.org/oyster/eifs/base-blue_v1.0.0_linux_arm64.eif"
                        .into(),
                ),
            },
            _ => Err(anyhow!("Image URL is required")),
        })?;

    // Create metadata
    let metadata = create_metadata(
        &selected_instance.instance,
        &args.region,
        selected_instance.memory,
        selected_instance.cpu,
        &image_url,
        &args.job_name,
        args.debug,
        &args
            .init_params
            .load(args.preset, args.arch, args.debug)
            .context("Failed to load init params")?
            .unwrap_or("".into()),
    );

    Ok((metadata, total_cost, total_rate))
}

async fn create_new_oyster_job_on_ethereum(
    metadata: String,
    provider_addr: Address,
    rate: U256,
    balance: U256,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider + Clone,
) -> Result<H256> {
    let market_address = OYSTER_MARKET_ADDRESS.parse::<Address>()?;

    // Load OysterMarket contract using Alloy
    let provider_clone = provider.clone();
    let market = OysterMarket::new(market_address, provider_clone);

    // Create job_open call
    let tx_hash = market
        .jobOpen(metadata, provider_addr, rate, balance)
        .send()
        .await?
        .watch()
        .await?;

    info!("Job creation transaction: {:?}", tx_hash);

    let job_id = get_receipt_and_job_id(tx_hash, provider).await?;

    Ok(job_id)
}

async fn get_receipt_and_job_id(
    tx_hash: H256,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider + Clone,
) -> Result<H256> {
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    // Add logging to check transaction status
    if !receipt.status() {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    let oyster_job_opened_event = "JobOpened(bytes32,string,address,address,uint256)";
    let oyster_job_opened_topic = keccak256(oyster_job_opened_event.as_bytes());

    // Look for JobOpened event
    for log in receipt.inner.logs().iter() {
        if log.topics()[0] == oyster_job_opened_topic {
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

async fn create_new_oyster_job_on_solana(
    metadata: String,
    provider_addr: Pubkey,
    rate: U256,
    balance: U256,
    provider: &AnchorClient<Rc<Keypair>>,
) -> Result<H256> {
    let program = provider
        .program(market_v::ID)
        .context("Failed to get program")?;

    let market = Pubkey::find_program_address(&[b"market"], &market_v::ID).0;
    let job_index = program
        .account::<SolanaMarketVMarket>(market)
        .await?
        .job_index;
    let job =
        Pubkey::find_program_address(&[b"job", job_index.to_le_bytes().as_ref()], &market_v::ID).0;
    let owner = program.payer();
    let token_mint = Pubkey::from_str(SOLANA_USDC_MINT_ADDRESS)?;
    let program_token_account =
        Pubkey::find_program_address(&[b"job_token", token_mint.as_ref()], &market_v::ID).0;

    let user_token_account = get_associated_token_address(&owner, &token_mint);
    let provider_token_account = get_associated_token_address(&provider_addr, &token_mint);
    let credit_mint = Pubkey::find_program_address(&[b"credit_mint"], &oyster_credits::ID).0;
    let program_credit_token_account =
        Pubkey::find_program_address(&[b"credit_token", credit_mint.as_ref()], &market_v::ID).0;
    let user_credit_token_account = get_associated_token_address(&owner, &credit_mint);
    let state = Pubkey::find_program_address(&[b"state"], &oyster_credits::ID).0;
    let credit_program_usdc_token_account =
        Pubkey::find_program_address(&[b"program_usdc"], &oyster_credits::ID).0;

    create_all_associated_token_accounts(
        &program.payer(),
        &provider_addr,
        &token_mint,
        &credit_mint,
        &program,
    )
    .await?;

    let signature: Signature = program
        .request()
        .accounts(SolanaMarketVJobOpen {
            market,
            job,
            owner,
            token_mint,
            program_token_account,
            user_token_account,
            provider_token_account,
            credit_mint,
            program_credit_token_account,
            user_credit_token_account,
            state,
            credit_program_usdc_token_account,
            token_program: token::ID,
            credit_program: oyster_credits::ID,
            system_program: system_program::ID,
        })
        .args(SolanaMarketVJobOpenArgs {
            metadata,
            provider: provider_addr,
            rate: rate.to::<u64>(),
            balance: balance.to::<u64>(),
        })
        .send()
        .await?;

    info!("Job creation signature: {:?}", signature);

    // sleep for 20 seconds
    info!("Sleeping for 20 seconds before fetching transaction receipt");
    sleep(StdDuration::from_secs(20)).await;

    let receipt = program
        .rpc()
        .get_transaction(&signature, UiTransactionEncoding::Json)
        .await;

    let Ok(receipt) = receipt else {
        return Err(anyhow!(
            "Failed to get transaction receipt: {:?}",
            receipt.unwrap_err()
        ));
    };

    if receipt.transaction.meta.is_none() {
        return Err(anyhow!("Failed to get transaction meta"));
    }

    let meta = receipt.transaction.meta.unwrap();

    if meta.err.is_some() {
        return Err(anyhow!("Transaction failed: {:?}", meta.err.unwrap()));
    }

    Ok(H256::from(U256::from(job_index)))
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

        let resp = client.get(&ip_url).send().await;
        let Ok(response) = resp else {
            tracing::error!("Failed to connect to IP endpoint: {}", resp.unwrap_err());
            tokio::time::sleep(StdDuration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

        // Get the status code
        let status = response.status();

        // Get text response first to log in case of error
        let text = response.text().await;
        let Ok(text_body) = text else {
            tracing::error!("Failed to read response body: {}", text.unwrap_err());
            tokio::time::sleep(StdDuration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

        // Parse the JSON
        let json_result = serde_json::from_str::<serde_json::Value>(&text_body);
        let Ok(json) = json_result else {
            let err = json_result.unwrap_err();
            tracing::error!(
                "Failed to parse IP endpoint response (status: {}): {}. Raw response: {}",
                status,
                err,
                text_body
            );
            tokio::time::sleep(StdDuration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

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

async fn get_ethereum_operator_cp(
    provider_address: &str,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider,
) -> Result<String> {
    let market_address = Address::from_str(OYSTER_MARKET_ADDRESS)?;
    let provider_address = Address::from_str(provider_address)?;

    // Create contract instance
    let market = OysterMarket::new(market_address, provider);

    // Call providers function to get CP URL
    let cp_url = market.providers(provider_address).call().await;

    match cp_url {
        Ok(cp_url) => Ok(cp_url.cp),
        Err(e) => {
            error!("Failed to get CP URL: {:?}", e);
            Err(anyhow!("Failed to get CP URL"))
        }
    }
}

async fn get_solana_operator_cp(
    provider_address: &str,
    provider: &AnchorClient<Rc<Keypair>>,
) -> Result<String> {
    let Ok(program) = provider.program(market_v::ID) else {
        return Err(anyhow!("Failed to get program"));
    };

    let provider_address =
        Pubkey::from_str(provider_address).context("Failed to parse provider address")?;

    let provider_address_pa =
        Pubkey::find_program_address(&[b"provider", provider_address.as_ref()], &market_v::ID).0;

    let operator = program
        .account::<SolanaMarketVProvider>(provider_address_pa)
        .await;

    match operator {
        Ok(operator) => Ok(operator.cp),
        Err(e) => {
            error!("Failed to get operator. Error: {:?}", e);
            Err(anyhow!("Failed to get operator"))
        }
    }
}
