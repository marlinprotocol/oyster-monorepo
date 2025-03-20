// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: u8 = 1;

pub const HTTP_CALL_RETRY_DELAY: u64 = 200; // Retry interval (in milliseconds) for HTTP requests
pub const GAS_LIMIT_BUFFER: u64 = 200000; // Fixed buffer to add to the estimated gas for setting gas limit
pub const TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const RESEND_TXN_INTERVAL: u64 = 5; // Interval (in secs) in which to confirm/resend pending/dropped txns
pub const RESEND_GAS_PRICE_INCREMENT_PERCENT: u64 = 10; // Gas price increment percent while resending pending/dropped txns
pub const MAX_OUTPUT_BYTES_LENGTH: usize = 20 * 1024; // 20kB, Maximum allowed serverless output size

// Event signatures of 'TeeManager' and 'Jobs' contracts
pub const EXECUTOR_REGISTERED_EVENT: &str =
    "TeeNodeRegistered(address,address,uint256,uint256,uint8)";
pub const EXECUTOR_DRAINED_EVENT: &str = "TeeNodeDrained(address)";
pub const EXECUTOR_REVIVED_EVENT: &str = "TeeNodeRevived(address)";
pub const EXECUTOR_DEREGISTERED_EVENT: &str = "TeeNodeDeregistered(address)";

pub const JOB_CREATED_EVENT: &str =
    "JobCreated(uint256,uint8,address,uint256,bytes32,bytes,uint256,address[])";
pub const JOB_RESPONDED_EVENT: &str = "JobResponded(uint256,address,bytes,uint256,uint8,uint8)";

// Code contract 'saveCodeInCalldata' function selector
pub const SAVE_CODE_FUNCTION_SELECTOR: &str = "0x1ae53fea";
