// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: u8 = 1;
pub const TIMEOUT_TXN_SEND_BUFFER_MS: u64 = 1000;
pub const TIMEOUT_TXN_RESEND_DEADLINE_SECS: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const MAX_OUTPUT_BYTES_LENGTH: usize = 20 * 1024; // 20kB, Maximum allowed serverless output size
pub const RPC_ERROR_RETRY_DELAY_SECS: u64 = 1;
pub const RPC_ERROR_MAX_RETRY_DELAY_SECS: u64 = 60; // Upper bound of the backoff between reconnect attempts
pub const RPC_REQUEST_TIMEOUT_SECS: u64 = 15; // Timeout for a single RPC request (block number, contract call, logs)
pub const REGISTRATION_CHECK_INTERVAL_SECS: u64 = 30; // Interval of the on-chain registration check while waiting to be registered
pub const DEFAULT_LOGS_BACKFILL_CHUNK_SIZE: u64 = 10000; // Default block range of a single 'eth_getLogs' query
pub const LOGS_SWEEP_INTERVAL_SECS: u64 = 10; // Interval of the 'eth_getLogs' sweep that catches logs the subscriptions missed
pub const RPC_REQUEST_RETRIES: u32 = 3; // Attempts of a single 'eth_getLogs' or block number query before giving up
pub const PROCESSED_LOGS_RETAIN_BLOCKS: u64 = 50000; // Blocks for which processed logs are remembered to skip duplicates
