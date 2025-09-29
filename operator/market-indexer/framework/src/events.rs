use alloy_primitives::U256;
use serde::Serialize;

/// Define the event structs we want to capture and store in the database
#[derive(Debug, Serialize)]
pub struct JobOpened {
    pub job_id: String,
    pub owner: String,
    pub provider: String,
    pub metadata: String,
    pub rate: U256,
    pub balance: U256,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct JobClosed {
    pub job_id: String,
}

#[derive(Debug, Serialize)]
pub struct JobDeposited {
    pub job_id: String,
    pub from: String,
    pub amount: U256,
}

#[derive(Debug, Serialize)]
pub struct JobSettled {
    pub job_id: String,
    pub amount: U256,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct JobMetadataUpdated {
    pub job_id: String,
    pub new_metadata: String,
}

#[derive(Debug, Serialize)]
pub struct JobWithdrew {
    pub job_id: String,
    pub to: String,
    pub amount: U256,
}

#[derive(Debug, Serialize)]
pub struct JobReviseRateInitiated {
    pub job_id: String,
    pub new_rate: U256,
}

#[derive(Debug, Serialize)]
pub struct JobReviseRateCancelled {
    pub job_id: String,
}

#[derive(Debug, Serialize)]
pub struct JobReviseRateFinalized {
    pub job_id: String,
    pub new_rate: U256,
}

#[derive(Debug)]
pub enum JobEvent {
    Opened(JobOpened),
    Closed(JobClosed),
    Deposited(JobDeposited),
    Withdrew(JobWithdrew),
    Settled(JobSettled),
    ReviseRateInitiated(JobReviseRateInitiated),
    ReviseRateCancelled(JobReviseRateCancelled),
    ReviseRateFinalized(JobReviseRateFinalized),
    MetadataUpdated(JobMetadataUpdated),
}
