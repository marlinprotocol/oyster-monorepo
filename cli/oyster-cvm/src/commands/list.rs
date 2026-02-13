use anyhow::{Context, Result};
use chrono::DateTime;
use clap::Args;
use prettytable::{Table, row};
use reqwest::Client;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

use crate::configs::{arb, bsc, sui};
use crate::deployment::Deployment;

const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
const SECONDS_PER_HOUR: u128 = 3600;
const BUFFER_SECONDS: u128 = 5 * 60;

/// List active jobs for a wallet address
#[derive(Args)]
pub struct ListArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Wallet address to query jobs for
    #[arg(short, long, required = true)]
    address: String,

    /// Number of most recent jobs to display (optional)
    #[arg(short, long)]
    count: Option<u32>,
}

#[derive(Debug)]
struct JobData {
    id: String,
    rate_per_hour: f64,
    current_balance: f64,
    time_remaining: f64,
    provider: String,
}

pub async fn list_jobs(args: ListArgs) -> Result<()> {
    let wallet_address = args.address;
    let count = args.count;

    info!("Listing active jobs for wallet address: {}", wallet_address);

    let (indexer_url, usdc_decimals) = match args.deployment {
        Deployment::Arbitrum => (arb::INDEXER_URL, arb::USDC_DECIMALS),
        Deployment::Bsc => (bsc::INDEXER_URL, bsc::USDC_DECIMALS),
        Deployment::Sui => (sui::INDEXER_URL, sui::USDC_DECIMALS),
    };

    let client = Client::new();
    let query = match args.deployment {
        Deployment::Arbitrum | Deployment::Sui => json!({
            "query": r#"
                query($owner: String!) {
                    allJobs(
                        filter: {
                            owner: { equalToInsensitive: $owner },
                        }
                        orderBy: CREATED_DESC
                    ) {
                        nodes {
                            id
                            balance
                            lastSettled
                            rate
                            provider
                        }
                    }
                }
            "#,
            "variables": {
                "owner": wallet_address,
            }
        }),
        Deployment::Bsc => json!({
            "query": r#"
                query($owner: String!) {
                    jobs(
                        orderBy: createdAt
                        orderDirection: desc
                        where: {owner: $owner}
                    ) {
                        id
                        balance
                        lastSettled
                        rate
                        provider
                    }
                }
            "#,
            "variables": {
                "owner": wallet_address,
            }
        }),
    };

    let mut request = client.post(indexer_url).json(&query);
    if let Deployment::Bsc = args.deployment {
        request = request.bearer_auth(bsc::INDEXER_API_KEY);
    }

    let response = request
        .send()
        .await
        .context("Failed to send GraphQL query")?;

    let data: Value = response
        .json()
        .await
        .context("Failed to parse GraphQL response")?;

    if let Some(errors) = data.get("errors") {
        anyhow::bail!("GraphQL query failed: {:?}", errors);
    }

    let nodes = match args.deployment {
        Deployment::Arbitrum | Deployment::Sui => data
            .get("data")
            .and_then(|data| data.get("allJobs"))
            .and_then(|all_jobs| all_jobs.get("nodes"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Deployment::Bsc => data
            .get("data")
            .and_then(|data| data.get("jobs"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };

    if nodes.is_empty() {
        info!("No active jobs found for address: {}", wallet_address);
        return Ok(());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut table = Table::new();
    table.add_row(row![
        "ID",
        "RATE (USDC/hour)",
        "BALANCE",
        "TIME REMAINING",
        "PROVIDER"
    ]);

    let processed_jobs: Vec<_> = nodes
        .iter()
        .filter_map(|node| process_job_data(node, now, args.deployment.clone(), usdc_decimals))
        .take(count.unwrap_or(nodes.len().try_into().unwrap()) as usize)
        .collect();

    if processed_jobs.is_empty() {
        info!(
            "No active jobs with positive balance found for address: {}",
            wallet_address
        );
        return Ok(());
    }

    processed_jobs.iter().for_each(|job| {
        table.add_row(row![
            job.id,
            format!("{:.4} USDC", job.rate_per_hour),
            format!("{:.4} USDC", job.current_balance),
            format_time_remaining(job.time_remaining),
            job.provider
        ]);
    });

    table.printstd();
    Ok(())
}

fn process_job_data(
    node: &Value,
    now: u64,
    deploy: Deployment,
    usdc_decimals: u8,
) -> Option<JobData> {
    let balance_scale: u128 = 10u128.pow(usdc_decimals as u32);

    let id = node
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    debug!(
        "Processing job {} with raw rate: {:?}",
        id,
        node.get("rate")
    );

    // Get raw rate value first to properly handle zero rates
    let rate_raw: u128 = node
        .get("rate")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())?;

    // Skip if rate is zero
    if rate_raw == 0 {
        debug!("Skipping job {} due to zero rate", id);
        return None;
    }
    let rate_per_hour_raw = rate_raw.saturating_mul(SECONDS_PER_HOUR);

    let balance_raw: u128 = node
        .get("balance")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())?;

    if balance_raw == 0 {
        debug!("Skipping job {} due to zero balance", id);
        return None;
    }
    let balance_scaled = if RATE_SCALE >= balance_scale {
        balance_raw.saturating_mul(RATE_SCALE / balance_scale)
    } else {
        balance_raw / (balance_scale / RATE_SCALE)
    };

    let last_settled = match deploy {
        Deployment::Arbitrum | Deployment::Sui => node
            .get("lastSettled")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(&format!("{s}Z")).ok())
            .map(|dt| dt.timestamp())?,
        Deployment::Bsc => node
            .get("lastSettled")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())?,
    };

    let now_ts = now as i64;

    if now_ts < last_settled {
        error!(
            "Job Settled time is in the future for job {}. Make sure your system clock is correct.",
            id
        );
        return None;
    }

    let delta_seconds = (now_ts - last_settled) as u128;

    // Consumed balance = rate_per_second * elapsed_seconds
    let consumed_scaled = rate_raw.saturating_mul(delta_seconds);

    if consumed_scaled >= balance_scaled {
        debug!(
            "Skipping job {} due to zero or negative current balance",
            id
        );
        return None;
    }

    let current_balance_scaled = balance_scaled.saturating_sub(consumed_scaled);

    let remaining_seconds = current_balance_scaled / rate_raw;

    if remaining_seconds <= BUFFER_SECONDS {
        debug!(
            "Skipping job {} due to insufficient time remaining after buffer",
            id
        );
        return None;
    }

    let time_remaining = (remaining_seconds - BUFFER_SECONDS) as f64 / 3600.0;

    let rate_per_hour = rate_per_hour_raw as f64 / RATE_SCALE as f64;

    let current_balance = current_balance_scaled as f64 / RATE_SCALE as f64;

    let provider = node
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    Some(JobData {
        id,
        rate_per_hour,
        current_balance,
        time_remaining,
        provider,
    })
}

fn format_time_remaining(hours: f64) -> String {
    let days = (hours / 24.0).floor();
    let remaining_hours = (hours % 24.0).floor();
    let minutes = ((hours * 60.0) % 60.0).floor();

    match (days as i64, remaining_hours as i64) {
        (d, _) if d > 0 => format!("{:.0}d {:.0}h {:.0}m", days, remaining_hours, minutes),
        (0, h) if h > 0 => format!("{:.0}h {:.0}m", remaining_hours, minutes),
        _ => format!("{:.0}m", minutes),
    }
}
