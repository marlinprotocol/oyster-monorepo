use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use alloy::primitives::{Address, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use multi_block_txns::TxnManager;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use SecretManagerContract::{acknowledgeStoreCall, acknowledgeStoreFailedCall, markStoreAliveCall};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SecretManagerContract,
    "./SecretManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    TeeManagerContract,
    "./TeeManager.json"
);

// Define the EIP-712 struct that matches your Solidity contract
sol! {
    #[derive(Debug)]
    struct Alive {
        uint256 signTimestamp;
    }

    #[derive(Debug)]
    struct Acknowledge {
        uint256 secretId;
        uint256 signTimestamp;
    }
}

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the secret store configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub config_port: u16,
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub tee_manager_contract_addr: Address,
    pub secret_manager_contract_addr: Address,
    pub num_selected_stores: u8,
    pub enclave_signer_file: String,
    pub acknowledgement_timeout: u64,
    pub mark_alive_timeout: u64,
}

// App data struct containing the necessary fields to run the secret store
#[derive(Debug)]
pub struct AppState {
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: RwLock<String>,
    pub tee_manager_contract_addr: Address,
    pub secret_manager_contract_addr: Address,
    pub num_selected_stores: u8,
    pub enclave_signer: PrivateKeySigner,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub enclave_owner: Mutex<Address>,
    pub http_rpc_txn_manager: Mutex<Option<Arc<TxnManager>>>,
    pub enclave_registered: AtomicBool,
    pub events_listener_active: Mutex<bool>,
    pub enclave_draining: AtomicBool,
    pub last_block_seen: AtomicU64,
    pub acknowledgement_timeout: u64,
    pub mark_alive_timeout: u64,
    pub secrets_awaiting_acknowledgement: Mutex<HashMap<U256, u8>>,
    pub secrets_created: Mutex<HashMap<U256, SecretCreatedMetadata>>,
    pub secrets_stored: Mutex<HashMap<U256, SecretMetadata>>,
    pub tx_sender: Sender<StoresTransaction>,
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
pub struct CreateSecret {
    pub secret_id: U256,
    pub encrypted_secret_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub owner: Address,
    pub size_limit: U256,
    pub end_timestamp: U256,
}

#[derive(Debug, Clone)]
pub struct SecretCreatedMetadata {
    pub secret_metadata: SecretMetadata,
    pub acknowledgement_deadline: Instant,
}

#[derive(Clone)]
pub enum StoresTransaction {
    AcknowledgeStore(acknowledgeStoreCall, Instant),
    AcknowledgeStoreFailed(acknowledgeStoreFailedCall),
    MarkStoreAlive(markStoreAliveCall),
}
