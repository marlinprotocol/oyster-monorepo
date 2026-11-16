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
                return parse_hex_rate(rate_str);
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

/// Parses a rate as published by a control plane, a hex string with or without `0x` prefix.
pub fn parse_hex_rate(rate: &str) -> Result<U256> {
    let digits = rate
        .strip_prefix("0x")
        .or_else(|| rate.strip_prefix("0X"))
        .unwrap_or(rate);

    if digits.is_empty() {
        anyhow::bail!("Empty rate '{rate}' from the control plane");
    }

    U256::from_str_radix(digits, 16)
        .with_context(|| format!("Failed to parse rate '{rate}' from the control plane"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_rate_parsing_does_not_panic_on_malformed_values() {
        assert_eq!(parse_hex_rate("0x10").unwrap(), U256::from(16));
        assert_eq!(parse_hex_rate("ff").unwrap(), U256::from(255));
        // used to slice at byte 2 and panic
        assert!(parse_hex_rate("").is_err());
        assert!(parse_hex_rate("0").is_ok());
        assert!(parse_hex_rate("é").is_err());
        assert!(parse_hex_rate("0x").is_err());
        assert!(parse_hex_rate("0xzz").is_err());
        assert!(parse_hex_rate(&format!("0x{}", "f".repeat(65))).is_err());
    }
}
