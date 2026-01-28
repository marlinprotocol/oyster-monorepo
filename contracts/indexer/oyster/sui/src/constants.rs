use std::time::Duration;

#[allow(dead_code)]
pub const RATE_SCALING_FACTOR: u64 = 10u64.pow(12);

/// BCS encoding identifier used in Sui checkpoint binary format
/// Value 1 indicates standard BCS serialization
pub const CHECKPOINT_BCS_ENCODING: u8 = 1;

/// Header key for token-based authentication
pub const GRPC_AUTH_TOKEN: &str = "x-token";

/// Maximum number of concurrent checkpoint fetches
/// Note: Higher concurrency can improve throughput if the server can handle it
/// Monitor for connection timeouts - reduce if you see errors
pub const DEFAULT_FETCH_CONCURRENCY: usize = 100;

/// Default timeout for RPC requests
/// Longer timeouts can cause cascading delays when servers are overloaded
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
