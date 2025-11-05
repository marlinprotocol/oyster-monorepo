pub mod bandwidth;

use alloy::primitives::U256;

/// Formats a U256 value as USDC with 6 decimal places
pub fn format_usdc(value: U256, extra_decimals: i64) -> f64 {
    value.to::<u128>() as f64 / 10f64.powi(18 - extra_decimals as i32)
}
