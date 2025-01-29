// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: u8 = 1;

pub const HTTP_CALL_RETRY_DELAY: u64 = 10; // Retry interval (in milliseconds) for HTTP requests
pub const GAS_LIMIT_BUFFER: u64 = 200000; // Fixed buffer to add to the estimated gas for setting gas limit
pub const TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const RESEND_TXN_INTERVAL: u64 = 5; // Interval (in secs) in which to confirm/resend pending/dropped txns
pub const RESEND_GAS_PRICE_INCREMENT_PERCENT: u64 = 10; // Gas price increment percent while resending pending/dropped txns
pub const MAX_OUTPUT_BYTES_LENGTH: usize = 20 * 1024; // 20kB, Maximum allowed serverless output size
