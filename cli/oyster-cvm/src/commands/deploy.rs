use crate::{
    args::{init_params::InitParamsArgs, wallet::WalletArgs},
    commands::log::{LogArgs, stream_logs},
    configs,
    deployment::{
        Deployment,
        adapter::{JOB_ID_NOT_FOUND, JobTransactionKind, TX_MAYBE_INCLUDED},
        get_deployment_adapter,
    },
    types::Platform,
    utils::{
        ask_yes_no,
        bandwidth::{calculate_bandwidth_cost, get_bandwidth_rate_for_region, parse_hex_rate},
        format_token_amount, is_interactive, parse_token_amount,
    },
};

use alloy::primitives::U256;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, time::Duration as StdDuration};
use sui_sdk_types::Address;
use tokio::net::TcpStream;
use tracing::{info, warn};

use super::simulate::{LOCAL_DEV_IMAGE, SimulateArgs, simulate};

// Retry Configuration
const IP_CHECK_RETRIES: u32 = 20;
const IP_CHECK_INTERVAL: u64 = 15;
const ATTESTATION_RETRIES: u32 = 20;
const ATTESTATION_INTERVAL: u64 = 15;
const TCP_CHECK_RETRIES: u32 = 20;
const TCP_CHECK_INTERVAL: u64 = 15;

// The control plane of an operator stops an enclave this long before its balance runs out
const OPERATOR_STOP_BUFFER_MINUTES: u32 = 5;

/// Deploy an Oyster CVM instance
#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Preset for parameters (e.g. blue)
    #[arg(long, default_value = "blue")]
    preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    arch: Platform,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// USDC coin ID for Sui chain based enclave payment (optional, will be picked automatically from user's account if not provided)
    #[arg(long)]
    usdc_coin: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,

    /// Operator address
    #[arg(long)]
    operator: Option<String>,

    /// URL of the enclave image
    #[arg(long)]
    image_url: Option<String>,

    /// Region for deployment
    #[arg(long, default_value = "ap-south-1")]
    region: String,

    /// Instance type (e.g. "r6g.large")
    #[arg(long)]
    instance_type: Option<String>,

    /// Sample value (in MB): 1024. Please ensure that the provided values are within the available system resources, keeping in mind that some resources are reserved for the host machine’s operation.
    #[arg(long)]
    enclave_memory: Option<u32>,

    /// Sample value : 4. Please ensure that the provided values are within the available system resources, keeping in mind that some resources are reserved for the host machine’s operation.
    #[arg(long)]
    enclave_cpu: Option<u32>,

    /// Optional bandwidth in KBps (default: 10)
    #[arg(long, default_value = "10")]
    bandwidth: u32,

    /// Duration in minutes
    #[arg(long, required_unless_present = "simulate")]
    duration_in_minutes: Option<u32>,

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

    /// Abort if the total cost of the job is above this many USDC (e.g. 1.5).
    /// The price comes from the operator's control plane, this bounds what it can make you pay.
    #[arg(long)]
    max_cost: Option<String>,

    /// Abort if the rate of the job is above this many USDC per hour (e.g. 0.1)
    #[arg(long)]
    max_rate: Option<String>,

    /// Do not ask for confirmation before paying for the job
    #[arg(short = 'y', long)]
    yes: bool,

    /// Simulate the enclave locally
    #[arg(long, conflicts_with = "image_url")]
    simulate: bool,

    /// Application ports to expose out of the local oyster simulation
    #[arg(long, requires = "simulate")]
    simulate_expose_ports: Vec<String>,
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
    // Start simulation if dry_run flag is opted
    if args.simulate {
        if args.preset == "blue" {
            return start_simulation(args).await;
        } else {
            return Err(anyhow!(
                "Dry run is only supported for blue images based deployments!"
            ));
        }
    }

    tracing::info!("Starting deployment...");

    let operator = parse_operator(&args.deployment, args.operator);

    // kept to tell the user how to get out of a job if the deployment fails after it is opened
    let deployment_name = args.deployment.as_str();
    let recovery_flags = recovery_flags(
        deployment_name,
        args.rpc.as_deref(),
        &args.wallet.command_hint(),
    );

    let mut deployment_adapter = get_deployment_adapter(
        args.deployment,
        args.rpc,
        args.auth_token,
        args.usdc_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    let provider = deployment_adapter
        .create_provider_with_wallet(&args.wallet.load_required()?)
        .await?;

    // Get CP URL using the configured provider
    let cp_url = deployment_adapter
        .get_operator_cp(&operator, &provider)
        .await
        .context("Failed to get CP URL")?
        .trim_end_matches('/')
        .to_owned();
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

    let extra_decimals = deployment_adapter.fetch_extra_decimals(&provider).await?;

    // Token amounts have 18 - EXTRA_DECIMALS decimals, rates are per second with 18 decimals
    let token_decimals = u32::try_from(18 - extra_decimals)
        .map_err(|_| anyhow!("Unexpected EXTRA_DECIMALS value {extra_decimals}"))?;
    let rate_decimals = 18;

    // Calculate costs
    // SAFETY: will be some value if simulation is not opted
    let duration_minutes = args.duration_in_minutes.unwrap();
    if duration_minutes == 0 {
        return Err(anyhow!("--duration-in-minutes must be greater than 0"));
    }
    if duration_minutes <= OPERATOR_STOP_BUFFER_MINUTES {
        warn!(
            "Operators stop an enclave about {} minutes before its balance runs out, a duration of {} minutes leaves no time to run.",
            OPERATOR_STOP_BUFFER_MINUTES, duration_minutes
        );
    }
    let duration_seconds = (duration_minutes as u64) * 60;
    let (total_cost, total_rate) = calculate_total_cost(
        &selected_instance,
        duration_seconds,
        args.bandwidth,
        &args.region,
        &cp_url,
        extra_decimals,
    )
    .await?;
    let hourly_rate = total_rate.saturating_mul(U256::from(3600));

    info!("Operator: {}", operator);
    info!(
        "Instance: {} in {}, {} minutes",
        selected_instance.instance, args.region, duration_minutes
    );
    info!(
        "Total cost: {} USDC",
        format_token_amount(total_cost, token_decimals)
    );
    info!(
        "Total rate: {} USDC/hour",
        format_token_amount(hourly_rate, rate_decimals)
    );

    // The price is whatever the operator's control plane answered, check it against the caps
    let max_cost = args
        .max_cost
        .as_deref()
        .map(|x| parse_token_amount(x, token_decimals))
        .transpose()
        .context("Failed to parse --max-cost")?;
    let max_hourly_rate = args
        .max_rate
        .as_deref()
        .map(|x| parse_token_amount(x, rate_decimals))
        .transpose()
        .context("Failed to parse --max-rate")?;
    check_price_caps(
        total_cost,
        hourly_rate,
        max_cost,
        max_hourly_rate,
        token_decimals,
    )
    .map_err(|err| {
        anyhow!(
            "{err}. The price was quoted by the operator's control plane at {cp_url}, nothing was paid"
        )
    })?;

    let image_url = args
        .image_url
        .map(Result::Ok)
        .unwrap_or(match args.preset.as_str() {
            "blue" => match args.arch {
                Platform::AMD64 => Ok(
                    "https://artifacts.marlin.org/oyster/eifs/base-blue_v3.0.0_linux_amd64.eif"
                        .into(),
                ),
                Platform::ARM64 => Ok(
                    "https://artifacts.marlin.org/oyster/eifs/base-blue_v3.0.0_linux_arm64.eif"
                        .into(),
                ),
            },
            _ => Err(anyhow!("Image URL is required")),
        })?;

    // Override memory and cpu if provided
    let selected_instance = InstanceRate {
        memory: args.enclave_memory.unwrap_or(selected_instance.memory),
        cpu: args.enclave_cpu.unwrap_or(selected_instance.cpu),
        ..selected_instance
    };

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

    // Nothing has been paid so far, the approval and the job open transaction follow
    if args.yes {
        info!("Skipping confirmation because of --yes");
    } else if is_interactive() {
        if !ask_yes_no(&format!(
            "Open the job and pay {} USDC to it?",
            format_token_amount(total_cost, token_decimals)
        ))? {
            return Err(anyhow!("Deployment cancelled, nothing was paid"));
        }
    } else {
        info!(
            "Not running in a terminal, continuing without confirmation. Use --max-cost and --max-rate to bound the price."
        );
    }

    // Approve USDC
    let funds = deployment_adapter
        .prepare_funds(total_cost, &provider)
        .await?;

    let job_create_transaction = deployment_adapter
        .create_job_transaction(
            JobTransactionKind::Create {
                metadata,
                operator,
                rate: total_rate,
                balance: total_cost,
            },
            Some(funds),
            &provider,
        )
        .await?;

    // Create job
    let job_id = match deployment_adapter
        .send_transaction(true, job_create_transaction, &provider)
        .await
    {
        Ok(Some(job_id)) => job_id,
        Ok(None) => {
            warn_job_may_be_open(
                deployment_name,
                &deployment_adapter.get_sender_address(),
                &recovery_flags,
            );
            return Err(anyhow!("Failed to get the Job ID"));
        }
        Err(err) => {
            let message = format!("{err:#}");
            if message.contains(TX_MAYBE_INCLUDED) || message.contains(JOB_ID_NOT_FOUND) {
                warn_job_may_be_open(
                    deployment_name,
                    &deployment_adapter.get_sender_address(),
                    &recovery_flags,
                );
            }
            return Err(err);
        }
    };
    info!("Job created with ID: {:?}", job_id);

    // The job is open and funded from here on. Whatever goes wrong below, the user has to
    // be told that it keeps billing and how to stop it.
    let ip_address = tokio::select! {
        result = wait_for_enclave(&cp_url, &job_id, &args.region) => match result {
            Ok(ip_address) => ip_address,
            Err(err) => {
                warn_job_is_billing(&job_id, &recovery_flags);
                return Err(err.context(format!(
                    "Job {job_id} was opened and funded but the enclave did not come up"
                )));
            }
        },
        _ = tokio::signal::ctrl_c() => {
            warn_job_is_billing(&job_id, &recovery_flags);
            return Err(anyhow!(
                "Interrupted while waiting for the enclave of job {job_id} to start"
            ));
        }
    };

    info!("Enclave is ready! IP address: {}", ip_address);

    if args.debug && !args.no_stream {
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

async fn wait_for_enclave(cp_url: &str, job_id: &str, region: &str) -> Result<String> {
    info!("Waiting for 3 minutes for enclave to start...");
    tokio::time::sleep(StdDuration::from_secs(180)).await;

    let ip_address = wait_for_ip_address(cp_url, job_id.to_owned(), region).await?;
    info!("IP address obtained: {}", ip_address);

    if !check_reachability(&ip_address).await {
        return Err(anyhow!("Reachability check failed after maximum retries"));
    }

    Ok(ip_address)
}

/// Flags shared by the commands suggested after a failed deployment.
fn recovery_flags(deployment: &str, rpc: Option<&str>, wallet_hint: &str) -> String {
    let mut flags = format!("--deployment {deployment}");
    if let Some(rpc) = rpc {
        flags.push_str(&format!(" --rpc {rpc}"));
    }
    flags.push(' ');
    flags.push_str(wallet_hint);
    flags
}

fn stop_command(job_id: &str, flags: &str) -> String {
    format!("oyster-cvm stop --job-id {job_id} {flags}")
}

fn withdraw_command(job_id: &str, flags: &str) -> String {
    format!("oyster-cvm withdraw --job-id {job_id} --max {flags}")
}

fn warn_job_is_billing(job_id: &str, flags: &str) {
    warn!(
        "Job {job_id} is open and funded. It keeps billing until it is stopped or its balance runs out."
    );
    warn!(
        "To stop it and get the unused balance back (billed until the stop completes, about 5 minutes):"
    );
    warn!("  {}", stop_command(job_id, flags));
    warn!("To take most of the balance out of the job right away, before stopping it:");
    warn!("  {}", withdraw_command(job_id, flags));
}

fn warn_job_may_be_open(deployment: &str, sender: &str, flags: &str) {
    warn!(
        "The job open transaction may have been included. If it was, a funded job exists and is billing."
    );
    warn!("Check for it with:");
    warn!("  oyster-cvm list --deployment {deployment} --address {sender}");
    warn!("and stop it with:");
    warn!("  {}", stop_command("<job id>", flags));
}

async fn start_simulation(args: DeployArgs) -> Result<()> {
    let simulate_args = SimulateArgs {
        docker_compose: args.init_params.docker_compose,
        docker_images: Vec::new(),
        init_params: args.init_params.init_params.unwrap_or_default(),
        expose_ports: args.simulate_expose_ports,
        dev_image: LOCAL_DEV_IMAGE.to_string(),
        container_memory: None,
        job_name: if args.job_name.is_empty() {
            "oyster_local_dev_container".to_string()
        } else {
            args.job_name
        },
        cleanup_cache: true,
        no_local_images: true,
    };

    simulate(simulate_args).await
}

fn parse_operator(deployment: &Deployment, operator: Option<String>) -> String {
    match deployment {
        Deployment::Arbitrum => {
            operator.unwrap_or(configs::arb::DEFAULT_OPERATOR_ADDRESS.to_string())
        }
        Deployment::Bsc => operator.unwrap_or(configs::bsc::DEFAULT_OPERATOR_ADDRESS.to_string()),
        Deployment::Sui => operator.unwrap_or(configs::sui::DEFAULT_OPERATOR_ADDRESS.to_string()),
    }
}

async fn fetch_operator_spec(url: &str) -> Result<Operator> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let operator: Operator = response.json().await?;
    Ok(operator)
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
            let a_rate = parse_hex_rate(&a.min_rate).unwrap_or(U256::MAX);
            let b_rate = parse_hex_rate(&b.min_rate).unwrap_or(U256::MAX);
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
    extra_decimals: i64,
) -> Result<(U256, U256)> {
    let instance_secondly_rate_usdc =
        parse_hex_rate(&instance_rate.min_rate).context("Failed to parse instance rate")?;
    let bandwidth_rate_region = get_bandwidth_rate_for_region(region, cp_url).await?;

    compute_total_cost(
        instance_secondly_rate_usdc,
        bandwidth_rate_region,
        bandwidth,
        duration,
        extra_decimals,
    )
}

/// Total cost in token base units and total rate (per second, 18 decimals) of a job.
fn compute_total_cost(
    instance_secondly_rate_usdc: U256,
    bandwidth_rate_region: U256,
    bandwidth: u32,
    duration: u64,
    extra_decimals: i64,
) -> Result<(U256, U256)> {
    let instance_cost_scaled = U256::from(duration)
        .checked_mul(instance_secondly_rate_usdc)
        .context("Failed to multiply duration and instance rate")?;

    let bandwidth_cost_scaled = calculate_bandwidth_cost(
        &bandwidth.to_string(),
        "KBps",
        bandwidth_rate_region,
        duration,
    )
    .context("Failed to calculate bandwidth cost")?;

    let bandwidth_rate_scaled = bandwidth_cost_scaled
        .checked_div(U256::from(duration))
        .context("Failed to divide bandwidth cost by duration")?;
    let scale = U256::from(10)
        .checked_pow(U256::from(
            u64::try_from(extra_decimals).context("Negative extra decimals")?,
        ))
        .context("Extra decimals too large")?;
    let total_cost_scaled = instance_cost_scaled
        .checked_add(bandwidth_cost_scaled)
        .context("Failed to add instance and bandwidth costs")?
        .checked_div(scale)
        .context("Failed to divide total cost by 1e12")?;
    let total_rate_scaled = instance_secondly_rate_usdc
        .checked_add(bandwidth_rate_scaled)
        .context("Failed to add instance and bandwidth rates")?;

    Ok((total_cost_scaled, total_rate_scaled))
}

/// Refuses a price above what the user is willing to pay.
/// Amounts are in token base units, rates in USDC per hour with 18 decimals.
fn check_price_caps(
    total_cost: U256,
    hourly_rate: U256,
    max_cost: Option<U256>,
    max_hourly_rate: Option<U256>,
    token_decimals: u32,
) -> Result<()> {
    if let Some(max_cost) = max_cost
        && total_cost > max_cost
    {
        return Err(anyhow!(
            "Total cost {} USDC is above --max-cost {} USDC",
            format_token_amount(total_cost, token_decimals),
            format_token_amount(max_cost, token_decimals)
        ));
    }
    if let Some(max_hourly_rate) = max_hourly_rate
        && hourly_rate > max_hourly_rate
    {
        return Err(anyhow!(
            "Rate {} USDC/hour is above --max-rate {} USDC/hour",
            format_token_amount(hourly_rate, 18),
            format_token_amount(max_hourly_rate, 18)
        ));
    }

    Ok(())
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

async fn wait_for_ip_address(url: &str, job_id: String, region: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let mut last_response = String::new();

    // Construct the IP endpoint URL with query parameters
    let ip_url = format!("{}/ip?id={}&region={}", url, job_id, region);

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
        if let Some(ip) = json.get("ip").and_then(|ip| ip.as_str())
            && !ip.is_empty()
        {
            return Ok(ip.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    // 0.05 USDC/hour
    const RATE: u64 = 13_888_888_888_889;

    #[test]
    fn total_cost_and_rate() {
        // no bandwidth, 60 minutes, 6 decimal token
        let (cost, rate) = compute_total_cost(U256::from(RATE), U256::ZERO, 10, 3600, 12).unwrap();
        assert_eq!(cost, U256::from(50_000));
        assert_eq!(rate, U256::from(RATE));

        // bandwidth rate is per GBps, the default is 10 KBps
        let bandwidth_rate = U256::from(1024u64 * 1024 * 1000);
        let (cost, rate) =
            compute_total_cost(U256::from(RATE), bandwidth_rate, 10, 3600, 12).unwrap();
        assert_eq!(rate, U256::from(RATE + 10_000));
        assert_eq!(cost, U256::from((RATE + 10_000) * 3600 / 10u64.pow(12)));
    }

    #[test]
    fn hostile_control_plane_values_are_errors_not_panics() {
        // rate that overflows once multiplied by the duration
        assert!(compute_total_cost(U256::MAX, U256::ZERO, 10, 3600, 12).is_err());
        assert!(compute_total_cost(U256::from(1), U256::MAX, 10, 3600, 12).is_err());
        // zero duration used to surface as a division error deep in the cost code
        assert!(compute_total_cost(U256::from(RATE), U256::ZERO, 10, 0, 12).is_err());
        // a rate beyond u128 is priced without panicking, the caps then refuse it
        let huge = U256::from(u128::MAX) * U256::from(4);
        let (cost, rate) = compute_total_cost(huge, U256::ZERO, 10, 60, 12).unwrap();
        let hourly = rate.saturating_mul(U256::from(3600));
        assert!(check_price_caps(cost, hourly, Some(U256::from(10_000_000)), None, 6).is_err());
        assert!(!format_token_amount(hourly, 18).is_empty());
    }

    #[test]
    fn price_caps() {
        let cost = U256::from(50_000); // 0.05 USDC
        let hourly = U256::from(RATE) * U256::from(3600);
        let cap = |x: &str, decimals| Some(parse_token_amount(x, decimals).unwrap());

        assert!(check_price_caps(cost, hourly, None, None, 6).is_ok());
        assert!(check_price_caps(cost, hourly, cap("0.05", 6), cap("0.06", 18), 6).is_ok());
        // a cap equal to the price passes
        assert!(check_price_caps(cost, hourly, cap("0.05", 6), None, 6).is_ok());
        assert_eq!(
            check_price_caps(cost, hourly, cap("0.049999", 6), None, 6)
                .unwrap_err()
                .to_string(),
            "Total cost 0.05 USDC is above --max-cost 0.049999 USDC"
        );
        assert!(check_price_caps(cost, hourly, None, cap("0.05", 18), 6).is_err());
        assert!(check_price_caps(cost, hourly, cap("1", 6), cap("0.01", 18), 6).is_err());
    }

    #[test]
    fn recovery_commands_carry_the_deployment_and_wallet() {
        let flags = recovery_flags("arb", None, "--wallet-file ./key.txt");
        assert_eq!(
            stop_command("0x32ad", &flags),
            "oyster-cvm stop --job-id 0x32ad --deployment arb --wallet-file ./key.txt"
        );
        assert_eq!(
            withdraw_command("0x32ad", &flags),
            "oyster-cvm withdraw --job-id 0x32ad --max --deployment arb --wallet-file ./key.txt"
        );
    }

    #[test]
    fn recovery_commands_carry_a_custom_rpc_but_never_the_key() {
        let flags = recovery_flags(
            "bsc",
            Some("https://rpc.example"),
            "--wallet-private-key <key>",
        );
        assert_eq!(
            stop_command("0x22", &flags),
            "oyster-cvm stop --job-id 0x22 --deployment bsc --rpc https://rpc.example --wallet-private-key <key>"
        );
    }
}
