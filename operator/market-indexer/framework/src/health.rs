use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone, Default)]
pub struct HealthTracker {
    inner: Arc<Mutex<HealthState>>,
}

#[derive(Default, Serialize, Clone)]
pub struct HealthState {
    pub healthy: bool,
    pub last_error: Option<String>,
    pub last_error_time: Option<SystemTime>,
    pub last_successful_block: Option<i64>,
    pub consecutive_errors: u64,
}

impl HealthTracker {
    pub fn new() -> Self {
        let state = HealthState {
            healthy: true,
            ..Default::default()
        };
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    pub fn record_success(&self, last_block: i64) {
        let mut state = self.inner.lock().unwrap();
        state.healthy = true;
        state.last_error = None;
        state.last_error_time = None;
        state.last_successful_block = Some(last_block);
        state.consecutive_errors = 0;
    }

    pub fn record_error(&self, msg: impl Into<String>) {
        let mut state = self.inner.lock().unwrap();
        state.healthy = false;
        state.last_error = Some(msg.into());
        state.last_error_time = Some(SystemTime::now());
        state.consecutive_errors = state.consecutive_errors.saturating_add(1);
    }

    pub fn get_status(&self) -> HealthState {
        self.inner.lock().unwrap().clone()
    }
}

/// Start health check HTTP server
pub async fn start_health_server(health: HealthTracker, port: u16) -> Result<()> {
    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(health);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Health check server listening on port {}", port);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_handler(State(health): State<HealthTracker>) -> (StatusCode, Json<Value>) {
    let status = health.get_status();
    let status_code = if status.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = json!({
        "healthy": status.healthy,
        "last_error": status.last_error,
        "last_error_time": status.last_error_time
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        "last_successful_block": status.last_successful_block,
        "consecutive_errors": status.consecutive_errors,
    });

    (status_code, Json(response))
}
