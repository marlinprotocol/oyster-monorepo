use alloy::primitives::U256;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ServerlessError {
    #[error("Failed to decode log")]
    LogDecodeFailure,
    #[error("Job does not belong to the enclave")]
    JobDoesNotBelongToEnclave,
    #[error("Job is older than the maintained block states")]
    JobOlderThanMaintainedBlockStates,
    #[error("No Gateways Registered in cycle: {0}")]
    NoGatewaysRegisteredInCycle(u64),
    #[error("No Gateways avaialble in cycle: {0} for the Request Chain: {1}")]
    NoValidGatewaysForChain(u64, u64),
    #[error("No Subscription Job found for the subscription id: {0}")]
    NoSubscriptionJobFound(U256),
    #[error("Failed to get logs: {0}")]
    LogsFetchFailure(String),
    #[error("Failed to get the block number: {0}")]
    BlockNumberFetchFailure(String),

    #[cfg(test)]
    #[error("Invalid topic")]
    InvalidTopic,

    #[cfg(test)]
    #[error("Empty Topics")]
    EmptyTopics,
}
