use actix_extensible_rate_limit::{
    RateLimiter,
    backend::{SimpleInput, SimpleInputFunctionBuilder, SimpleOutput, memory::InMemoryBackend},
};
use actix_web::dev::ServiceRequest;
use std::future::Ready;
use std::time::Duration;

/// Creates a new RateLimiter with specified duration and maximum requests.
///
/// # Arguments
///
/// * `duration` - The time window for rate limiting.
/// * `max_requests` - The maximum number of requests allowed within the duration.
///
/// # Returns
///
/// A configured RateLimiter instance.
pub fn get_rate_limiter(
    duration: Duration,
    max_requests: u64,
) -> RateLimiter<
    InMemoryBackend,
    SimpleOutput,
    impl Fn(&ServiceRequest) -> Ready<Result<SimpleInput, actix_web::Error>> + 'static,
> {
    let backend = InMemoryBackend::builder().build();
    let input = SimpleInputFunctionBuilder::new(duration, max_requests)
        .real_ip_key()
        .build();

    RateLimiter::builder(backend.clone(), input)
        .add_headers()
        .build()
}
