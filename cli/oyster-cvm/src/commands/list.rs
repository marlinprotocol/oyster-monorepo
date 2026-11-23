use anyhow::{Context, Result};
use chrono::DateTime;
use clap::Args;
use prettytable::{Table, row};
use reqwest::Client;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use alloy::primitives::U256;

use crate::configs::{arb, bsc, sui};
use crate::deployment::Deployment;
use crate::utils::{accrued_since_settlement, format_token_display, mispricing_warning};

const SECONDS_PER_HOUR: u64 = 3600;
const BUFFER_SECONDS: u64 = 5 * 60;

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
    rate_per_hour: String,
    current_balance: String,
    time_remaining: f64,
    provider: String,
}

pub async fn list_jobs(args: ListArgs) -> Result<()> {
    let wallet_address = args.address;
    let count = args.count;

    info!("Listing active jobs for wallet address: {}", wallet_address);

    let (indexer_url, usdc_decimals, extra_decimals) = match args.deployment {
        Deployment::Arbitrum => (
            arb::INDEXER_URL,
            arb::USDC_DECIMALS,
            arb::MARKET_EXTRA_DECIMALS,
        ),
        Deployment::Bsc => (
            bsc::INDEXER_URL,
            bsc::USDC_DECIMALS,
            bsc::MARKET_EXTRA_DECIMALS,
        ),
        Deployment::Sui => (
            sui::INDEXER_URL,
            sui::USDC_DECIMALS,
            sui::MARKET_EXTRA_DECIMALS,
        ),
    };
    if let Some(warning) = mispricing_warning(usdc_decimals as u32, extra_decimals as i64) {
        warn!("{warning}");
    }

    let client = Client::new();
    let query = json!({
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
    });

    let response = client
        .post(indexer_url)
        .json(&query)
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

    let nodes = data
        .get("data")
        .and_then(|data| data.get("allJobs"))
        .and_then(|all_jobs| all_jobs.get("nodes"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

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
        .filter_map(|node| process_job_data(node, now, usdc_decimals, extra_decimals))
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
            format!("{} USDC", job.rate_per_hour),
            format!("{} USDC", job.current_balance),
            format_time_remaining(job.time_remaining),
            job.provider
        ]);
    });

    table.printstd();
    Ok(())
}

/// Works out the live balance of a job from its last settled state, the way the market
/// settles it: `ceil(rate * elapsed / 10^extra_decimals)` base units of the token are used up.
/// Returns None for jobs that are out of balance or within the buffer of running out.
fn process_job_data(
    node: &Value,
    now: u64,
    usdc_decimals: u8,
    extra_decimals: u8,
) -> Option<JobData> {
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
    let rate: U256 = node
        .get("rate")
        .and_then(|v| v.as_str())
        .and_then(|s| U256::from_str_radix(s, 10).ok())?;

    // Skip if rate is zero
    if rate.is_zero() {
        debug!("Skipping job {} due to zero rate", id);
        return None;
    }

    let balance: U256 = node
        .get("balance")
        .and_then(|v| v.as_str())
        .and_then(|s| U256::from_str_radix(s, 10).ok())?;

    if balance.is_zero() {
        debug!("Skipping job {} due to zero balance", id);
        return None;
    }

    let last_settled = node
        .get("lastSettled")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(&format!("{s}Z")).ok())
        .map(|dt| dt.timestamp())?;

    let now_ts = now as i64;

    if now_ts < last_settled {
        error!(
            "Job Settled time is in the future for job {}. Make sure your system clock is correct.",
            id
        );
        return None;
    }

    // Consumed balance in token base units, as the market computes it
    let consumed = accrued_since_settlement(rate, last_settled, now, extra_decimals as i64);

    if consumed >= balance {
        debug!(
            "Skipping job {} due to zero or negative current balance",
            id
        );
        return None;
    }

    let current_balance = balance - consumed;

    let scale = U256::from(10).pow(U256::from(extra_decimals));
    let remaining_seconds = (current_balance.saturating_mul(scale) / rate).saturating_to::<u64>();

    if remaining_seconds <= BUFFER_SECONDS {
        debug!(
            "Skipping job {} due to insufficient time remaining after buffer",
            id
        );
        return None;
    }

    let time_remaining = (remaining_seconds - BUFFER_SECONDS) as f64 / 3600.0;

    // rate / 10^extra_decimals base units per second
    let rate_per_hour = format_token_display(
        rate.saturating_mul(U256::from(SECONDS_PER_HOUR)),
        usdc_decimals as u32 + extra_decimals as u32,
    );

    let current_balance = format_token_display(current_balance, usdc_decimals as u32);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(rate: &str, balance: &str, last_settled: &str) -> Value {
        json!({
            "id": "0x01",
            "rate": rate,
            "balance": balance,
            "lastSettled": last_settled,
            "provider": "0xabc",
        })
    }

    // 2026-01-01T00:00:00Z
    const T0: u64 = 1_767_225_600;

    #[test]
    fn arbitrum_job_shows_balance_and_rate() {
        // 0.05 USDC/hour, 1 USDC, one hour in
        let job = process_job_data(
            &node("13888888888889", "1000000", "2026-01-01T00:00:00"),
            T0 + 3600,
            6,
            12,
        )
        .unwrap();
        assert_eq!(job.rate_per_hour, "0.05");
        assert_eq!(job.current_balance, "0.949999");
        // 0.949999 USDC lasts just under 19 hours, minus the 5 minute buffer
        assert!((job.time_remaining - (19.0 - 5.0 / 60.0)).abs() < 0.01);
    }

    #[test]
    fn bsc_job_is_listed_with_its_real_amounts() {
        // review M-5: BSC job 0, rate 14225699361165, balance 12803 base units of an
        // 18 decimal token for 15 minutes. It used to be filtered out as expired.
        let job = process_job_data(
            &node("14225699361165", "12803", "2026-01-01T00:00:00"),
            T0 + 300,
            18,
            12,
        )
        .unwrap();
        assert_eq!(job.current_balance, "0.000000000000008535");
        assert_eq!(job.rate_per_hour, "0.0000000000000512125");
        // 10 of 15 minutes left, minus the 5 minute buffer
        assert!((job.time_remaining - 5.0 / 60.0).abs() < 0.01);
    }

    #[test]
    fn bsc_job_with_a_large_deposit_does_not_overflow() {
        // jobs 3 to 5 on BSC hold 3.85e16 base units, 1e12 times the runtime of job 0
        let job = process_job_data(
            &node("14225699361165", "38500000000000000", "2026-01-01T00:00:00"),
            T0 + 400 * 86400,
            18,
            12,
        )
        .unwrap();
        assert_eq!(job.current_balance, "0.0384999");
        assert!(job.time_remaining > 1e9);
    }

    #[test]
    fn expired_and_empty_jobs_are_hidden() {
        let expired = node("13888888888889", "1000000", "2026-01-01T00:00:00");
        assert!(process_job_data(&expired, T0 + 30 * 3600, 6, 12).is_none());
        // inside the 5 minute buffer
        assert!(process_job_data(&expired, T0 + 20 * 3600 - 200, 6, 12).is_none());
        let zero_rate = node("0", "1000000", "2026-01-01T00:00:00");
        assert!(process_job_data(&zero_rate, T0, 6, 12).is_none());
        let zero_balance = node("13888888888889", "0", "2026-01-01T00:00:00");
        assert!(process_job_data(&zero_balance, T0, 6, 12).is_none());
    }
}
