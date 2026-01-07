use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::interval;

const STARTUP_GRACE_SECS: u64 = 300;
const UNHEALTHY_CONSECUTIVE_ERRORS: u64 = 5;
const DEGRADED_CONSECUTIVE_ERRORS: u64 = 3;
const UNHEALTHY_ERROR_RATE: f64 = 0.30;
const DEGRADED_ERROR_RATE: f64 = 0.15;
const UNHEALTHY_STALE_SECS: u64 = 180;
const DEGRADED_STALE_SECS: u64 = 60;
const INDEXER_HEALTH_CALL_TIMEOUT_SECS: u64 = 2;
const INDEXER_HEALTH_POLL_INTERVAL_SECS: u64 = 10;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub reason: Option<String>,
}

#[derive(Clone)]
struct CachedIndexerHealthState {
    status: HealthStatus,
    reason: Option<String>,
    last_updated: SystemTime,
}

#[derive(Clone)]
pub struct IndexerHealthTracker {
    state: Arc<Mutex<CachedIndexerHealthState>>,
}

impl Default for IndexerHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexerHealthTracker {
    pub fn new() -> Self {
        let state = CachedIndexerHealthState {
            status: HealthStatus::Unhealthy,
            reason: None,
            last_updated: SystemTime::now(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn spawn_polling_task(&self, indexer_url: String) -> Result<()> {
        let client = Client::builder()
            .timeout(Duration::from_secs(INDEXER_HEALTH_CALL_TIMEOUT_SECS))
            .build()
            .context("Failed to build HTTP client")?;
        let state = self.clone();

        tokio::spawn(async move {
            poll_indexer_health(indexer_url.as_str(), client, state.clone()).await
        });

        Ok(())
    }

    pub fn get_report(&self) -> HealthReport {
        let state = self.state.lock().unwrap().clone();
        let now = SystemTime::now();

        if now
            .duration_since(state.last_updated)
            .unwrap_or(Duration::MAX)
            > Duration::from_secs(INDEXER_HEALTH_POLL_INTERVAL_SECS * 3)
        {
            return HealthReport {
                status: HealthStatus::Unhealthy,
                reason: Some("indexer_health_stale".into()),
            };
        }

        HealthReport {
            status: state.status,
            reason: state.reason,
        }
    }

    #[cfg(test)]
    pub fn set_test_status(&self, status: HealthStatus, reason: Option<String>) {
        let mut state = self.state.lock().unwrap();
        state.status = status;
        state.reason = reason;
        state.last_updated = SystemTime::now();
    }
}

#[derive(Clone)]
struct HealthState {
    start_time: SystemTime,
    last_success: SystemTime,
    recent_checks: VecDeque<bool>,
    last_error: Option<String>,
}

#[derive(Clone)]
pub struct HealthTracker {
    state: Arc<Mutex<HealthState>>,
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthTracker {
    pub fn new() -> Self {
        let now = SystemTime::now();
        let state = HealthState {
            start_time: now,
            last_success: now,
            recent_checks: VecDeque::new(),
            last_error: None,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn record_success(&self) {
        let mut state = self.state.lock().unwrap();
        state.last_success = SystemTime::now();
        state.last_error = None;
        state.recent_checks.push_back(true);
        Self::trim(&mut state.recent_checks);
    }

    pub fn record_error(&self, msg: impl Into<String>) {
        let mut state = self.state.lock().unwrap();
        state.last_error = Some(msg.into());
        state.recent_checks.push_back(false);
        Self::trim(&mut state.recent_checks);
    }

    pub fn get_report(&self) -> HealthReport {
        let state = self.state.lock().unwrap().clone();
        let now = SystemTime::now();

        let uptime = now.duration_since(state.start_time).unwrap_or_default();
        let time_since_success = now
            .duration_since(state.last_success)
            .unwrap_or(Duration::MAX);

        let consecutive_errors = Self::count_consecutive(&state.recent_checks, false);
        let error_rate = Self::error_rate(&state.recent_checks);

        let unhealthy = consecutive_errors >= UNHEALTHY_CONSECUTIVE_ERRORS
            || error_rate > UNHEALTHY_ERROR_RATE
            || time_since_success > Duration::from_secs(UNHEALTHY_STALE_SECS);

        if unhealthy && uptime < Duration::from_secs(STARTUP_GRACE_SECS) {
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

        if consecutive_errors >= DEGRADED_CONSECUTIVE_ERRORS
            || error_rate > DEGRADED_ERROR_RATE
            || time_since_success > Duration::from_secs(DEGRADED_STALE_SECS)
        {
            return HealthReport {
                status: HealthStatus::Degraded,
                reason: Some("intermittent_errors_or_staleness".into()),
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

async fn poll_indexer_health(indexer_url: &str, client: Client, health: IndexerHealthTracker) {
    let mut interval = interval(Duration::from_secs(INDEXER_HEALTH_POLL_INTERVAL_SECS));

    loop {
        interval.tick().await;

        let result = client
            .get(format!("{}/health", indexer_url))
            .send()
            .await
            .and_then(|r| r.error_for_status());

        match result {
            Ok(resp) => {
                let report_json = resp.json::<HealthReport>().await;
                let mut guard = health.state.lock().unwrap();

                match report_json {
                    Ok(report) => {
                        *guard = CachedIndexerHealthState {
                            status: report.status,
                            reason: report.reason,
                            last_updated: SystemTime::now(),
                        };
                    }
                    Err(_) => {
                        *guard = CachedIndexerHealthState {
                            status: HealthStatus::Unhealthy,
                            reason: Some("indexer_health_parse_failed".into()),
                            last_updated: SystemTime::now(),
                        };
                    }
                }
            }
            Err(_) => {
                let mut guard = health.state.lock().unwrap();
                *guard = CachedIndexerHealthState {
                    status: HealthStatus::Unhealthy,
                    reason: Some("indexer_unreachable".into()),
                    last_updated: SystemTime::now(),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_starts_healthy() {
        let tracker = HealthTracker::new();
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.reason.is_none());
    }

    #[test]
    fn test_health_tracker_uptime_consecutive_errors() {
        let tracker = HealthTracker::new();

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
        let tracker = HealthTracker::new();

        {
            let mut state = tracker.state.lock().unwrap();
            state.start_time = SystemTime::now() - Duration::from_secs(400);
        }

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
        let tracker = HealthTracker::new();

        {
            let mut state = tracker.state.lock().unwrap();
            state.start_time = SystemTime::now() - Duration::from_secs(400);
        }

        for _ in 0..6 {
            tracker.record_success();
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
        let tracker = HealthTracker::new();

        {
            let mut state = tracker.state.lock().unwrap();
            state.start_time = SystemTime::now() - Duration::from_secs(400);
            state.last_success = SystemTime::now() - Duration::from_secs(200); // > 180s
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("sustained_errors"));
    }

    #[test]
    fn test_health_tracker_recovery() {
        let tracker = HealthTracker::new();

        {
            let mut state = tracker.state.lock().unwrap();
            state.start_time = SystemTime::now() - Duration::from_secs(400);
        }

        for _ in 0..5 {
            tracker.record_error("test error");
        }
        assert_eq!(tracker.get_report().status, HealthStatus::Unhealthy);

        for _ in 0..30 {
            tracker.record_success();
        }
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_indexer_health_tracker_starts_unhealthy() {
        let tracker = IndexerHealthTracker::new();
        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_none());
    }

    #[test]
    fn test_indexer_health_tracker_stale() {
        let tracker = IndexerHealthTracker::new();

        {
            let mut state = tracker.state.lock().unwrap();
            state.last_updated = SystemTime::now() - Duration::from_secs(35); // > 30s (3*10)
        }

        let report = tracker.get_report();
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.reason.is_some());
        assert!(report.reason.unwrap().contains("stale"));
    }
}
