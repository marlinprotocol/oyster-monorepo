use alloy::primitives::U256;

// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: U256 = U256::ONE;
pub const TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const MAX_OUTPUT_BYTES_LENGTH: usize = 20 * 1024; // 20kB, Maximum allowed serverless output size
