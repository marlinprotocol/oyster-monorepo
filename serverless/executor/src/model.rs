use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, U256};
use alloy::sol;
use k256::ecdsa::SigningKey;
use multi_block_txns::TxnManager;
use serde::{Deserialize, Serialize};
use JobsContract::{slashOnExecutionTimeoutCall, submitOutputCall};

use crate::cgroups::Cgroups;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    JobsContract,
    "./Jobs.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CodeContract,
    "./CodeContract.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ExecutorsContract,
    "./TeeManager.json"
);

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
    pub tee_manager_contract_addr: Address,
    pub jobs_contract_addr: Address,
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
    pub enclave_address: Address,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Arc<Mutex<bool>>,
    pub mutable_params_injected: Arc<Mutex<bool>>,
    pub enclave_registered: Arc<AtomicBool>,
    pub events_listener_active: Arc<Mutex<bool>>,
    pub enclave_draining: Arc<AtomicBool>,
    pub enclave_owner: Arc<Mutex<Address>>,
    pub http_rpc_txn_manager: Arc<Mutex<Option<Arc<TxnManager>>>>,
    pub last_block_seen: Arc<AtomicU64>,
    pub job_requests_running: Arc<Mutex<HashSet<U256>>>,
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
    pub enclave_address: Address,
    pub enclave_public_key: String,
    pub owner_address: Address,
    pub executor_gas_address: Address,
    pub secret_store_gas_address: String,
    pub ws_rpc_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegistrationMessage {
    pub job_capacity: usize,
    pub storage_capacity: usize,
    pub sign_timestamp: u64,
    pub env: U256,
    pub owner: Address,
    pub signature: String,
}

#[derive(Clone)]
pub enum JobsTransaction {
    OUTPUT(submitOutputCall, u64),
    TIMEOUT(slashOnExecutionTimeoutCall),
}
