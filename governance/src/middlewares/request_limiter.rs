// src/middlewares/request_limiter.rs

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use futures::future::{Ready, ok};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Middleware to limit the number of concurrent requests.
#[derive(Clone)]
pub struct ConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimiter {
    /// Creates a new `ConcurrencyLimiter` with the specified maximum number of concurrent requests.
    pub fn new(max_concurrent: usize) -> Self {
        ConcurrencyLimiter {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ConcurrencyLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ConcurrencyLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ConcurrencyLimiterMiddleware {
            service: Arc::new(service),
            semaphore: self.semaphore.clone(),
        })
    }
}

/// Middleware service that enforces concurrency limits.
pub struct ConcurrencyLimiterMiddleware<S> {
    service: Arc<S>,
    semaphore: Arc<Semaphore>,
}

impl<S, B> Service<ServiceRequest> for ConcurrencyLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let semaphore = self.semaphore.clone();
        let service = self.service.clone();

        match semaphore.try_acquire_owned() {
            Ok(permit) => {
                // If a permit is acquired, proceed with the request
                Box::pin(async move {
                    // Hold the permit for the duration of the request
                    let _permit = permit;

                    // Process the request
                    let res = service.call(req).await?;

                    // Map the response body to EitherBody::Left
                    Ok(res.map_into_left_body())
                })
            }
            Err(_) => {
                // If no permits are available, reject the request with 503
                Box::pin(async move {
                    let response = HttpResponse::ServiceUnavailable()
                        .body("Too many concurrent requests. Please try again later.")
                        .map_into_right_body();
                    Ok(req.into_response(response))
                })
            }
        }
    }
}
