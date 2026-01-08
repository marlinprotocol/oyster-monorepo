use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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

#[derive(Clone, Serialize, PartialEq, Debug)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Serialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct HealthConfig {
    pub startup_grace: Duration,
    pub unhealthy_consecutive_errors: u64,
    pub degraded_consecutive_errors: u64,
    pub unhealthy_error_rate: f64,
    pub degraded_error_rate: f64,
    pub unhealthy_stale: Duration,
    pub degraded_stale: Duration,
    pub unhealthy_lag: i64,
    pub degraded_lag: i64,
}

#[derive(Clone)]
struct HealthState {
    start_time: SystemTime,
    last_progress: SystemTime,
    last_successful_block: Option<i64>,
    latest_chain_block: Option<i64>,
    recent_checks: VecDeque<bool>,
    last_error: Option<String>,
}

#[derive(Clone)]
pub struct HealthTracker {
    state: Arc<Mutex<HealthState>>,
    config: HealthConfig,
}

impl HealthTracker {
    pub fn new(config: HealthConfig) -> Self {
        let now = SystemTime::now();
        let state = HealthState {
            start_time: now,
            last_progress: now,
            last_successful_block: None,
            latest_chain_block: None,
            recent_checks: VecDeque::new(),
            last_error: None,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            config,
        }
    }

    pub fn record_progress(&self, block: i64) {
        let mut state = self.state.lock().unwrap();
        state.last_progress = SystemTime::now();
        state.last_error = None;
        state.last_successful_block = Some(block);
        state.recent_checks.push_back(true);
        Self::trim(&mut state.recent_checks);
    }

    pub fn record_error(&self, msg: impl Into<String>) {
        let mut state = self.state.lock().unwrap();
        state.last_error = Some(msg.into());
        state.recent_checks.push_back(false);
        Self::trim(&mut state.recent_checks);
    }

    pub fn update_chain_head(&self, block: i64) {
        let mut state = self.state.lock().unwrap();
        state.latest_chain_block = Some(block);
    }

    pub fn get_report(&self) -> HealthReport {
        let state = self.state.lock().unwrap().clone();
        let now = SystemTime::now();

        let uptime = now.duration_since(state.start_time).unwrap_or_default();
        let time_since_progress = now
            .duration_since(state.last_progress)
            .unwrap_or(Duration::MAX);

        let consecutive_errors = Self::count_consecutive(&state.recent_checks, false);
        let error_rate = Self::error_rate(&state.recent_checks);

        let mut freshness_degraded = false;

        if let (Some(head), Some(indexed)) = (state.latest_chain_block, state.last_successful_block)
        {
            let lag = head - indexed;

            if lag > self.config.unhealthy_lag {
                return HealthReport {
                    status: HealthStatus::Unhealthy,
                    reason: Some("chain_lag_too_high".into()),
                };
            }

            if lag > self.config.degraded_lag {
                freshness_degraded = true;
            }
        }

        let unhealthy = consecutive_errors >= self.config.unhealthy_consecutive_errors
            || error_rate > self.config.unhealthy_error_rate
            || time_since_progress > self.config.unhealthy_stale;

        if unhealthy && uptime < self.config.startup_grace {
            return HealthReport {
                status: HealthStatus::Degraded,
                reason: Some("startup_instability".into()),
            };
        }

        if unhealthy {
            return HealthReport {
                status: HealthStatus::Unhealthy,
                reason: Some("sustained_errors_or_stall".into()),
            };
        }

        if freshness_degraded
            || consecutive_errors >= self.config.degraded_consecutive_errors
            || error_rate > self.config.degraded_error_rate
            || time_since_progress > self.config.degraded_stale
        {
            return HealthReport {
                status: HealthStatus::Degraded,
                reason: Some("lag_or_intermittent_errors".into()),
            };
        }

        HealthReport {
            status: HealthStatus::Healthy,
            reason: None,
        }
    }

    fn trim(buf: &mut VecDeque<bool>) {
        const MAX: usize = 100;
        while buf.len() > MAX {
            buf.pop_front();
        }
    }

    fn count_consecutive(buf: &VecDeque<bool>, value: bool) -> u64 {
        buf.iter().rev().take_while(|&&v| v == value).count() as u64
    }

    fn error_rate(buf: &VecDeque<bool>) -> f64 {
        if buf.is_empty() {
            return 0.0;
        }
        let errors = buf.iter().filter(|&&v| !v).count();
        errors as f64 / buf.len() as f64
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
    let report = health.get_report();

    let code = match report.status {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (
        code,
        Json(json!({
            "status": report.status,
            "reason": report.reason,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HealthConfig {
        HealthConfig {
            startup_grace: Duration::from_secs(300),
            unhealthy_consecutive_errors: 5,
            degraded_consecutive_errors: 3,
            unhealthy_error_rate: 0.30,
            degraded_error_rate: 0.15,
            unhealthy_stale: Duration::from_secs(180),
            degraded_stale: Duration::from_secs(60),
            unhealthy_lag: 10,
            degraded_lag: 5,
        }
    }

    #[test]
    fn test_health_tracker_starts_healthy() {
        let tracker = HealthTracker::new(test_config());
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.reason.is_none());
    }

    #[test]
    fn test_health_tracker_record_progress() {
        let tracker = HealthTracker::new(test_config());
        tracker.record_progress(100);
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Healthy);

        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_successful_block, Some(100));
    }

    #[test]
    fn test_health_tracker_uptime_consecutive_errors() {
        let tracker = HealthTracker::new(test_config());

        for _ in 0..5 {
            tracker.record_error("test error");
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Degraded);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("startup_instability"));
    }

    #[test]
    fn test_health_tracker_unhealthy_consecutive_errors() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        for _ in 0..5 {
            tracker.record_error("test error");
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("sustained_errors"));
    }

    #[test]
    fn test_health_tracker_error_rate() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        for _ in 0..6 {
            tracker.record_progress(100);
        }
        for _ in 0..4 {
            tracker.record_error("test error");
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("sustained_errors"));
    }

    #[test]
    fn test_health_tracker_staleness() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        {
            let mut state = tracker.state.lock().unwrap();
            state.last_progress = SystemTime::now() - Duration::from_secs(200);
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("sustained_errors"));
    }

    #[test]
    fn test_health_tracker_lag_unhealthy() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        tracker.record_progress(100);
        tracker.update_chain_head(120);

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("chain_lag_too_high"));
    }

    #[test]
    fn test_health_tracker_lag_degraded() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        tracker.record_progress(100);
        tracker.update_chain_head(108);

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Degraded);
        assert!(report.reason.is_some());
        assert!(
            report
                .reason
                .unwrap()
                .contains("lag_or_intermittent_errors")
        );
    }

    #[test]
    fn test_health_tracker_recovery() {
        let mut config = test_config();
        config.startup_grace = Duration::from_secs(0);
        let tracker = HealthTracker::new(config);

        for _ in 0..5 {
            tracker.record_error("test error");
        }
        assert_eq!(tracker.get_report().status, HealthStatus::Unhealthy);

        for i in 0..30 {
            tracker.record_progress(100 + i);
        }
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Healthy);
    }
}
