use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;
use ethers::abi::Abi;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::LocalWallet;
use ethers::types::{Address, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};

use crate::cgroups::Cgroups;

pub type HttpSignerProvider = SignerMiddleware<Provider<Http>, LocalWallet>;

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the executor configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub secret_store_config_port: u16,
    pub workerd_runtime_path: String,
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub tee_manager_contract_addr: H160,
    pub jobs_contract_addr: H160,
    pub code_contract_addr: String,
    pub enclave_signer_file: String,
    pub execution_buffer_time: u64,
    pub num_selected_executors: u8,
}

// App data struct containing the necessary fields to run the executor
#[derive(Debug, Clone)]
pub struct AppState {
    pub cgroups: Arc<Mutex<Cgroups>>,
    pub job_capacity: usize,
    pub secret_store_config_port: u16,
    pub workerd_runtime_path: String,
    pub secret_store_path: String,
    pub execution_buffer_time: u64,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub ws_rpc_url: Arc<RwLock<String>>,
    pub tee_manager_contract_addr: Address,
    pub jobs_contract_addr: Address,
    pub code_contract_addr: String,
    pub num_selected_executors: u8,
    pub enclave_address: H160,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Arc<Mutex<bool>>,
    pub mutable_params_injected: Arc<Mutex<bool>>,
    pub enclave_registered: Arc<AtomicBool>,
    pub events_listener_active: Arc<Mutex<bool>>,
    pub enclave_draining: Arc<AtomicBool>,
    pub enclave_owner: Arc<Mutex<H160>>,
    pub http_rpc_client: Arc<Mutex<Option<HttpSignerProvider>>>,
    pub jobs_contract_abi: Abi,
    pub job_requests_running: Arc<Mutex<HashSet<U256>>>,
    pub last_block_seen: Arc<AtomicU64>,
    pub nonce_to_send: Arc<Mutex<U256>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImmutableConfig {
    pub owner_address_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MutableConfig {
    pub executor_gas_key: String,
    pub secret_store_gas_key: String,
    pub ws_api_key: String,
}

#[derive(Serialize)]
pub struct TeeConfig {
    pub enclave_address: H160,
    pub enclave_public_key: String,
    pub owner_address: H160,
    pub executor_gas_address: H160,
    pub secret_store_gas_address: String,
    pub ws_rpc_url: String,
}

#[derive(Serialize)]
pub struct RegistrationMessage {
    pub job_capacity: usize,
    pub storage_capacity: usize,
    pub sign_timestamp: u64,
    pub env: u8,
    pub owner: H160,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JobsTxnType {
    OUTPUT,
    TIMEOUT,
}

impl JobsTxnType {
    pub fn as_str(&self) -> &str {
        match self {
            JobsTxnType::OUTPUT => "output",
            JobsTxnType::TIMEOUT => "timeout",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct JobOutput {
    pub output: Bytes,
    pub error_code: u8,
    pub total_time: u128,
    pub sign_timestamp: U256,
    pub signature: Bytes,
}

#[derive(Debug, Clone)]
pub struct JobsTxnMetadata {
    pub txn_type: JobsTxnType,
    pub job_id: U256,
    pub job_output: Option<JobOutput>,
    pub gas_estimate_block: Option<u64>,
    pub retry_deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingTxnData {
    pub txn_hash: H256,
    pub txn_data: JobsTxnMetadata,
    pub http_rpc_client: HttpSignerProvider,
    pub nonce: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub last_monitor_instant: Instant,
}

pub enum JobsTxnSendError {
    NonceTooLow,
    NonceTooHigh,
    OutOfGas,
    GasTooHigh,
    GasPriceLow,
    ContractExecution,
    NetworkConnectivity,
    OtherRetryable,
}
