use alloy::primitives::U256;
use once_cell::sync::Lazy;

pub const REQUEST_RELAY_TIMEOUT: u64 = 40;

// pub const RESPONSE_RELAY_TIMEOUT: u64 = 40;
pub const MAX_GATEWAY_RETRIES: u8 = 2;
pub const MAX_TX_RECEIPT_RETRIES: u8 = 5;
pub const MAX_RETRY_ON_PROVIDER_ERROR: u8 = 5;

pub const GATEWAY_BLOCK_STATES_TO_MAINTAIN: u64 = 5;
pub const WAIT_BEFORE_HTTP_RPC_CALL: u64 = 100;

pub const MIN_GATEWAY_STAKE: Lazy<U256> =
    Lazy::new(|| U256::from(111_111_111_111_111_110_000 as u128));
pub const GATEWAY_STAKE_ADJUSTMENT_FACTOR: Lazy<U256> = Lazy::new(|| U256::from(1e18 as u128));

// Event signatures
pub const COMMON_CHAIN_GATEWAY_REGISTERED_EVENT: &str =
    "GatewayRegistered(address,address,uint256[])";
pub const COMMON_CHAIN_GATEWAY_DEREGISTERED_EVENT: &str = "GatewayDeregistered(address)";
pub const COMMON_CHAIN_GATEWAY_CHAIN_ADDED_EVENT: &str = "ChainAdded(address,uint256)";
pub const COMMON_CHAIN_GATEWAY_CHAIN_REMOVED_EVENT: &str = "ChainRemoved(address,uint256)";

pub const REQUEST_CHAIN_GATEWAY_REGISTERED_EVENT: &str = "GatewayRegistered(address,address)";

pub const REQUEST_CHAIN_JOB_RELAYED_EVENT: &str =
    "JobRelayed(uint256,uint8,bytes32,bytes,uint256,uint256,uint256,uint256,address,address,uint256,uint256,address)";
pub const REQUEST_CHAIN_JOB_CANCELLED_EVENT: &str = "JobCancelled(uint256)";
pub const REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT: &str =
    "JobSubscriptionStarted(uint256,uint8,address,uint256,uint256,uint256,uint256,address,bytes32,bytes,uint256)";
pub const REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT: &str =
    "JobSubscriptionJobParamsUpdated(uint256,bytes32,bytes)";
pub const REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT: &str =
    "JobSubscriptionTerminationParamsUpdated(uint256,uint256)";

pub const COMMON_CHAIN_JOB_RELAYED_EVENT: &str =
    "JobRelayed(uint256,uint256,uint8,address,address)";
pub const COMMON_CHAIN_JOB_RESPONDED_EVENT: &str = "JobResponded(uint256,bytes,uint256,uint8)";
pub const COMMON_CHAIN_JOB_RESOURCE_UNAVAILABLE_EVENT: &str =
    "JobResourceUnavailable(uint256,address)";
pub const COMMON_CHAIN_GATEWAY_REASSIGNED_EVENT: &str =
    "GatewayReassigned(uint256,address,address,uint8)";

pub const COMMON_CHAIN_TXN_CALL_TIMEOUT: u64 = 60;
pub const REQUEST_CHAIN_TXN_CALL_TIMEOUT: u64 = 60;
