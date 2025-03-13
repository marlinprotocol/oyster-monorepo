use alloy::primitives::U256;

/// Extract the first 8 bytes (chain ID) from Job ID - a U256 value
pub fn extract_chain_id(value: U256) -> u64 {
    (value >> 192_u32).to::<u64>()
}
