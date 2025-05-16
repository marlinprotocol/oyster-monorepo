use alloy::primitives::U256;
use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};

pub fn to_eth(wei: U256) -> Result<f64> {
    let wei_f64: f64 = wei
        .to_string()
        .parse()
        .context("Failed to parse wei amount to f64")?;
    Ok(wei_f64 / 1e18)
}

pub fn to_usdc(base_units: U256) -> Result<f64> {
    let units_f64: f64 = base_units
        .to_string()
        .parse()
        .context("Failed to parse USDC base units to f64")?;
    Ok(units_f64 / 1e6)
}

pub fn string_epoch_to_local_datetime(epoch: String) -> Result<String> {
    let epoch_i64 = epoch.parse::<i64>()?;
    let utc_time = DateTime::<Utc>::from_timestamp(epoch_i64, 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid epoch timestamp"))?;
    let local_time = utc_time.with_timezone(&Local);
    Ok(local_time.to_string())
}
