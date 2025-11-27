use alloy::primitives::U256;
use anyhow::{Context, Result};

pub struct BandwidthUnit {
    pub id: &'static str,
    pub value: U256,
}

pub const OYSTER_BANDWIDTH_UNITS_LIST: [BandwidthUnit; 3] = [
    BandwidthUnit {
        id: "KBps",
        value: U256::from_limbs([1024 * 1024, 0, 0, 0]),
    },
    BandwidthUnit {
        id: "MBps",
        value: U256::from_limbs([1024, 0, 0, 0]),
    },
    BandwidthUnit {
        id: "GBps",
        value: U256::from_limbs([1, 0, 0, 0]),
    },
];

pub async fn get_bandwidth_rate_for_region(region_code: &str, cp_url: &str) -> Result<U256> {
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/bandwidth", cp_url)).send().await?;
    let bandwidth_data: serde_json::Value = response.json().await?;

    // Extract rates array from response
    if let Some(rates) = bandwidth_data.get("rates").and_then(|r| r.as_array()) {
        // Find matching region and parse its rate
        for rate in rates {
            if let (Some(code), Some(rate_str)) = (
                rate.get("region_code").and_then(|c| c.as_str()),
                rate.get("rate").and_then(|r| r.as_str()),
            ) && code == region_code
            {
                // Parse hex rate string (removing "0x" prefix) to u256
                let rate_u256 = U256::from_str_radix(&rate_str[2..], 16)
                    .context("Failed to parse bandwidth rate")?;
                return Ok(rate_u256);
            }
        }
    }

    Err(anyhow::anyhow!("Region not found or parsing failed"))
}

pub fn calculate_bandwidth_cost(
    bandwidth: &str,
    bandwidth_unit: &str,
    bandwidth_rate_for_region_scaled: U256,
    duration: u64,
) -> Result<U256> {
    let unit_conversion_divisor = OYSTER_BANDWIDTH_UNITS_LIST
        .iter()
        .find(|unit| unit.id == bandwidth_unit)
        .map(|unit| unit.value)
        .context("Failed to find bandwidth unit")?;

    let bandwidth_u256 = bandwidth
        .parse::<U256>()
        .context("Failed to parse bandwidth as U256")?;

    (bandwidth_u256)
        .checked_mul(bandwidth_rate_for_region_scaled)
        .context("Failed to multiply bandwidth and bandwidth rate")?
        .checked_mul(U256::from(duration))
        .context("Failed to multiply duration and bandwidth rate")?
        .checked_div(unit_conversion_divisor)
        .context("Failed to divide by unit conversion divisor")
}
