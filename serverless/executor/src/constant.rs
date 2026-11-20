// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: u8 = 1;
pub const TIMEOUT_TXN_SEND_BUFFER_MS: u64 = 1000;
pub const TIMEOUT_TXN_RESEND_DEADLINE_SECS: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const MAX_OUTPUT_BYTES_LENGTH: usize = 20 * 1024; // 20kB, Maximum allowed serverless output size
pub const RPC_ERROR_RETRY_DELAY_SECS: u64 = 1;
pub const RPC_ERROR_MAX_RETRY_DELAY_SECS: u64 = 60; // Upper bound of the backoff between reconnect attempts
pub const RPC_REQUEST_TIMEOUT_SECS: u64 = 15; // Timeout for a single RPC request (block number, contract call, logs)
pub const REGISTRATION_CHECK_INTERVAL_SECS: u64 = 30; // Interval of the on-chain registration check while waiting to be registered
