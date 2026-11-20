use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use multi_block_txns::TxnManager;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone, Debug)]
pub struct AppState {
    pub enclave_signer_key: SigningKey,
    pub enclave_address: Address,
    pub wallet: Arc<RwLock<String>>,
    pub common_chain_id: u64,
    pub common_chain_http_url: String,
    pub common_chain_ws_url: String,
    pub gateways_contract_addr: Address,
    pub gateway_jobs_contract_addr: Address,
    pub request_chain_ids: Arc<Mutex<HashSet<u64>>>,
    pub registered: Arc<AtomicBool>,
    pub epoch: u64,
    pub time_interval: u64,
    pub offset_for_epoch: u64,
    pub gateways_start_block: u64,
    pub enclave_owner: Arc<Mutex<Address>>,
    pub immutable_params_injected: Arc<Mutex<bool>>,
    pub mutable_params_injected: Arc<AtomicBool>,
    pub registration_events_listener_active: Arc<Mutex<bool>>,
    // the check of the on chain registration at start-up has been started
    pub registration_check_started: Arc<AtomicBool>,
    // serializes the check of the on chain registration with the export of a registration message
    pub registration_check_lock: Arc<tokio::sync::Mutex<()>>,
    pub contracts_client: Arc<Mutex<Option<Arc<ContractsClient>>>>,
    pub ws_api_key: Arc<RwLock<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImmutableConfig {
    pub owner_address_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MutableConfig {
    pub gas_key_hex: String,
    pub ws_api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRegistrationBody {
    pub chain_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedRegistrationResponse {
    pub owner: Address,
    pub sign_timestamp: usize,
    pub chain_ids: Vec<u64>,
    pub common_chain_signature: String,
    pub request_chain_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayDetailsResponse {
    pub enclave_public_key: String,
    pub enclave_address: Address,
    pub owner_address: Address,
    pub gas_address: Address,
    pub ws_api_key: String,
}

pub enum RegisterType {
    CommonChain,
    RequestChain,
}

pub struct RegisteredData {
    pub register_type: RegisterType,
    pub chain_id: Option<u64>,
}

pub struct ConfigManager {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub common_chain_id: u64,
    pub common_chain_http_url: String,
    pub common_chain_ws_url: String,
    pub gateways_contract_addr: Address,
    pub gateway_jobs_contract_addr: Address,
    pub enclave_secret_key: String,
    pub epoch: u64,
    pub time_interval: u64,
    pub offset_for_epoch: u64,
    // block to start reading the gateways contract events from, usually its deployment block
    #[serde(default)]
    pub gateways_start_block: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayData {
    pub last_block_number: u64,
    pub address: Address,
    pub stake_amount: U256,
    pub req_chain_ids: BTreeSet<u64>,
    pub draining: bool,
}

#[derive(Debug, Clone)]
pub struct ContractsClient {
    pub enclave_owner: Address,
    pub enclave_signer_key: SigningKey,
    pub enclave_address: Address,
    pub common_chain_ws_url: String,
    pub common_chain_http_url: String,
    pub gateways_contract_address: Address,
    pub gateway_jobs_contract_address: Address,
    pub common_chain_txn_manager: Arc<TxnManager>,
    pub request_chains_data: Arc<RwLock<HashMap<u64, RequestChainData>>>,
    pub gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    pub request_chain_ids: HashSet<u64>,
    pub active_jobs: Arc<RwLock<HashMap<U256, Job>>>,
    pub current_jobs: Arc<RwLock<HashMap<U256, Job>>>,
    pub epoch: u64,
    pub time_interval: u64,
    pub offset_for_epoch: u64,
    pub gateways_start_block: u64,
    pub gateway_epoch_state_waitlist: Arc<RwLock<HashMap<u64, Vec<Job>>>>,
    pub common_chain_start_block_number: Arc<Mutex<u64>>,
    pub subscription_job_instance_heap: Arc<RwLock<BinaryHeap<SubscriptionJobInstanceHeap>>>,
    pub subscription_jobs: Arc<RwLock<HashMap<U256, SubscriptionJob>>>,
    pub ws_api_key: Arc<RwLock<String>>,
}

#[derive(Debug, Clone)]
pub struct RequestChainData {
    pub chain_id: u64,
    pub relay_address: Address,
    pub relay_subscriptions_address: Address,
    pub ws_rpc_url: String,
    pub http_rpc_url: String,
    pub request_chain_start_block_number: u64,
    pub confirmation_blocks: u64,
    pub last_seen_block: Arc<AtomicU64>,
    pub request_chain_txn_manager: Arc<TxnManager>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayJobType {
    JobRelay,
    SlashGatewayJob,
    JobResponded,
    // SlashGatewayResponse,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JobMode {
    Once,
    Subscription,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub job_id: U256,
    pub request_chain_id: u64,
    pub tx_hash: FixedBytes<32>,
    pub code_input: Bytes,
    pub user_timeout: U256,
    pub starttime: u64,
    pub job_owner: Address,
    pub job_type: GatewayJobType,
    pub sequence_number: u8,
    pub gateway_address: Option<Address>,
    pub job_mode: JobMode,
    pub env: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseJob {
    pub job_id: U256,
    pub request_chain_id: u64,
    pub output: Bytes,
    pub total_time: U256,
    pub error_code: u8,
    pub job_type: GatewayJobType,
    pub gateway_address: Option<Address>,
    pub job_mode: JobMode,
    // pub sequence_number: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JobSubscriptionAction {
    Add,
}

#[derive(Debug, Clone)]
pub struct JobSubscriptionChannelType {
    pub subscription_action: JobSubscriptionAction,
    pub subscription_id: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionJob {
    pub subscription_id: U256,
    pub request_chain_id: u64,
    pub subscriber: Address,
    pub interval: u64,
    pub termination_time: u64,
    pub user_timeout: U256,
    pub tx_hash: FixedBytes<32>,
    pub code_input: Bytes,
    pub starttime: u64,
    pub env: u8,
}

#[derive(Debug, Clone)]
pub struct SubscriptionJobInstanceHeap {
    pub subscription_id: U256,
    pub next_trigger_time: u64,
}
