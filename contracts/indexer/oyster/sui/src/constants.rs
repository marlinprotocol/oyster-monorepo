use std::time::Duration;

#[allow(dead_code)]
pub const RATE_SCALING_FACTOR: u64 = 10u64.pow(12);

/// Header key for token-based authentication
pub const GRPC_AUTH_TOKEN: &str = "x-token";

/// Maximum number of concurrent checkpoint fetches
pub const DEFAULT_FETCH_CONCURRENCY: usize = 200;

/// Default timeout for RPC requests
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
