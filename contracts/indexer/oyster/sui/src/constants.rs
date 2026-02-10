use std::time::Duration;

#[allow(dead_code)]
pub const RATE_SCALING_FACTOR: u64 = 10u64.pow(12);

/// BCS encoding identifier used in Sui checkpoint binary format
/// Value 1 indicates standard BCS serialization
pub const CHECKPOINT_BCS_ENCODING: u8 = 1;

/// Header key for token-based authentication
pub const GRPC_AUTH_TOKEN: &str = "x-token";

/// Maximum number of concurrent checkpoint fetches
/// Sui's own indexer framework uses 200 concurrency.
/// Monitor for connection timeouts - reduce if you see errors
pub const DEFAULT_FETCH_CONCURRENCY: usize = 200;

/// Timeout for gRPC requests (small payloads with narrowed FieldMask)
/// Shorter timeouts allow faster retries on slow/overloaded servers
pub const DEFAULT_GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for HTTP checkpoint downloads (.chk files contain full checkpoint data)
/// Needs to be longer than gRPC since these are large BCS-encoded blobs
pub const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// HTTP connection pool idle timeout
pub const DEFAULT_HTTP_CONNECTION_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

// HTTP connection pool keepalive timeout
pub const DEFAULT_HTTP_CONNECTION_POOL_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default cache TTL for latest_block() during catch-up
/// During historical sync the tip is millions ahead; no need to query every iteration
pub const DEFAULT_LATEST_BLOCK_CACHE_TTL: Duration = Duration::from_secs(30);

// Default max gRPC message size (matches Sui's official indexer framework)
pub const DEFAULT_MAX_GRPC_MESSAGE_SIZE: usize = 128 * 1024 * 1024;

// Default worker threads for tokio runtime
pub const DEFAULT_TOKIO_WORKER_THREADS: usize = 4;
