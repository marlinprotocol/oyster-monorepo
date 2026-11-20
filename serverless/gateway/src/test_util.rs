use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, Address, FixedBytes, Log as InnerLog, LogData, B256, U256};
use alloy::rpc::types::{Filter, Log};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::utils::public_key_to_address;
use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;
use axum_test::TestServer;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use serde_json::json;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api_impl::{
    export_signed_registration_message, get_gateway_details, index, inject_immutable_config,
    inject_mutable_config,
};
use crate::chain_util::HttpProviderLogs;
use crate::constant::{
    COMMON_CHAIN_JOB_RELAYED_EVENT, MIN_GATEWAY_STAKE,
    REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT,
    REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT,
    REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT,
};
use crate::error::ServerlessError;
use crate::model::{AppState, ContractsClient, GatewayData, Job, SubscriptionJob};

// Testnet or Local blockchain (Hardhat) configurations
#[cfg(test)]
pub const CHAIN_ID: u64 = 421614;
#[cfg(test)]
const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
#[cfg(test)]
const WS_URL: &str = "wss://arbitrum-sepolia.infura.io/ws/v3/cd72f20b9fd544f8a5b8da706441e01c";
#[cfg(test)]
const GATEWAYS_CONTRACT_ADDR: &str = "0x9a79Bb5676c19A01ad27D88ca6A0131d51022AC4";
#[cfg(test)]
pub const GATEWAY_JOBS_CONTRACT_ADDR: &str = "0x124371e1E13f2917A73E8eca9F361e6aA21eA06a";
#[cfg(test)]
pub const RELAY_CONTRACT_ADDR: &str = "0x1Af94DA972cC2B12dbfcb2871d62e531e4d4f1F0";
#[cfg(test)]
const SUBSCRIPTION_RELAY_CONTRACT_ADDR: &str = "0xA37F74824dA3DDaF241461c11f069Ebd2cc44b1a";
#[cfg(test)]
pub const OWNER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
#[cfg(test)]
pub const GAS_WALLET_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
#[cfg(test)]
pub const GAS_WALLET_PUBLIC_ADDRESS: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
#[cfg(test)]
const EPOCH: u64 = 1713433800;
#[cfg(test)]
const TIME_INTERVAL: u64 = 20;
#[cfg(test)]
const OFFSET_FOR_EPCOH: u64 = 4;
#[cfg(test)]
pub const CODE_HASH: Lazy<FixedBytes<32>> = Lazy::new(|| {
    let bytes = hex::decode("9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e")
        .expect("Invalid hex string");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    FixedBytes::from(arr)
});
#[cfg(test)]
pub const WS_API_KEY: &str = "abcdef_RbVpNrezyxZEvO6AnnCuO-kxt";

#[cfg(test)]
pub fn new_app(app_state: AppState) -> Router<()> {
    Router::new()
        .route("/", get(index))
        .route("/immutable-config", post(inject_immutable_config))
        .route("/mutable-config", post(inject_mutable_config))
        .route("/gateway-details", get(get_gateway_details))
        .route(
            "/signed-registration-message",
            post(export_signed_registration_message),
        )
        .with_state(app_state)
}

#[cfg(test)]
pub async fn generate_app_state() -> AppState {
    // Initialize random 'secp256k1' signing key for the enclave

    use std::sync::RwLock;

    let signer_key = SigningKey::random(&mut OsRng);

    AppState {
        enclave_signer_key: signer_key.clone(),
        enclave_address: public_key_to_address(&signer_key.verifying_key()),
        wallet: Arc::new(RwLock::new(String::new())),
        common_chain_id: CHAIN_ID,
        common_chain_http_url: HTTP_RPC_URL.to_owned(),
        common_chain_ws_url: WS_URL.to_owned(),
        gateways_contract_addr: GATEWAYS_CONTRACT_ADDR.parse::<Address>().unwrap(),
        gateway_jobs_contract_addr: GATEWAY_JOBS_CONTRACT_ADDR.parse::<Address>().unwrap(),
        request_chain_ids: Arc::new(Mutex::new(HashSet::new())),
        registered: Arc::new(AtomicBool::new(false)),
        registration_events_listener_active: Arc::new(Mutex::new(false)),
        registration_check_started: Arc::new(AtomicBool::new(false)),
        registration_check_lock: Arc::new(tokio::sync::Mutex::new(())),
        epoch: EPOCH,
        time_interval: TIME_INTERVAL,
        offset_for_epoch: OFFSET_FOR_EPCOH,
        gateways_start_block: 0,
        enclave_owner: Arc::new(Mutex::new(Address::ZERO)),
        immutable_params_injected: Arc::new(Mutex::new(false)),
        mutable_params_injected: Arc::new(AtomicBool::new(false)),
        contracts_client: Arc::new(Mutex::new(None)),
        ws_api_key: Arc::new(RwLock::new(String::new())),
    }
}

#[cfg(test)]
pub async fn generate_contracts_client() -> Arc<ContractsClient> {
    let app_state = generate_app_state().await;

    let server = TestServer::new(new_app(app_state.clone())).unwrap();
    // add immutable config
    let _resp = server
        .post("/immutable-config")
        .json(&json!({
            "owner_address_hex": OWNER_ADDRESS
        }))
        .await;
    // add mutable config
    let _resp = server
        .post("/mutable-config")
        .json(&json!({
            "gas_key_hex": GAS_WALLET_KEY,
            "ws_api_key": WS_API_KEY,
        }))
        .await;
    // Get signature with valid data points
    let _resp = server
        .post("/signed-registration-message")
        .json(&json!({
            "chain_ids": [CHAIN_ID]
        }))
        .await;
    let contracts_client = app_state.contracts_client.lock().unwrap().clone().unwrap();

    contracts_client
}

#[cfg(test)]
pub async fn add_gateway_epoch_state(
    contracts_client: Arc<ContractsClient>,
    num: Option<u64>,
    add_self: Option<bool>,
    cycle_delta: Option<i64>,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cycle = (((ts - contracts_client.epoch - contracts_client.offset_for_epoch)
        / contracts_client.time_interval) as i64
        + cycle_delta.unwrap_or(0)) as u64;

    let add_self = add_self.unwrap_or(true);

    let mut gateway_epoch_state_guard = contracts_client.gateway_epoch_state.write().unwrap();

    let mut num = num.unwrap_or(1);

    if add_self {
        gateway_epoch_state_guard
            .entry(cycle)
            .or_insert(BTreeMap::new())
            .insert(
                contracts_client.enclave_address,
                GatewayData {
                    last_block_number: 5600 as u64,
                    address: contracts_client.enclave_address,
                    stake_amount: U256::from(2) * (*MIN_GATEWAY_STAKE),
                    req_chain_ids: BTreeSet::from([CHAIN_ID]),
                    draining: false,
                },
            );

        num -= 1;
    }

    for _ in 0..num {
        let random_address = PrivateKeySigner::random().address();
        gateway_epoch_state_guard
            .entry(cycle)
            .or_insert(BTreeMap::new())
            .insert(
                random_address,
                GatewayData {
                    last_block_number: 5600 as u64,
                    address: random_address,
                    stake_amount: U256::from(2) * (*MIN_GATEWAY_STAKE),
                    req_chain_ids: BTreeSet::from([CHAIN_ID]),
                    draining: false,
                },
            );
    }
}

#[cfg(test)]
pub struct MockHttpProvider {
    pub job: Option<Job>,
    pub latest_block: u64,
}

#[cfg(test)]
impl MockHttpProvider {
    pub fn new(job: Option<Job>, latest_block: u64) -> Self {
        Self { job, latest_block }
    }
}

#[cfg(test)]
impl HttpProviderLogs for MockHttpProvider {
    async fn get_latest_block_number(&self) -> Result<u64, ServerlessError> {
        Ok(self.latest_block)
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError> {
        if filter.has_topics() {
            let topic0 = &filter.topics[0];

            // Mock logs for gateways_job_relayed_logs
            if topic0.matches(&keccak256(COMMON_CHAIN_JOB_RELAYED_EVENT)) {
                let job = self.job.clone().unwrap();
                if job.job_id == U256::from(1) {
                    Ok(vec![Log {
                        inner: InnerLog {
                            address: Address::from_str(GATEWAY_JOBS_CONTRACT_ADDR).unwrap(),
                            data: LogData::new_unchecked(
                                vec![
                                    keccak256(COMMON_CHAIN_JOB_RELAYED_EVENT).into(),
                                    U256::from(job.job_id).into(),
                                ],
                                DynSolValue::Tuple(vec![
                                    DynSolValue::Uint(U256::from(100), 256),
                                    DynSolValue::Uint(U256::from(1), 8),
                                    DynSolValue::Address(job.job_owner),
                                    DynSolValue::Address(job.gateway_address.unwrap()),
                                ])
                                .abi_encode()
                                .into(),
                            ),
                        },
                        ..Default::default()
                    }])
                } else {
                    Ok(vec![Log {
                        inner: InnerLog {
                            address: Address::default(),
                            data: LogData::new_unchecked(
                                vec![B256::default(), B256::default(), B256::default()],
                                DynSolValue::Tuple(vec![]).abi_encode().into(),
                            ),
                        },
                        ..Default::default()
                    }])
                }
            }
            // Mock logs for request_chain_job_subscription_started_event
            else if topic0.matches(&keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT)) {
                let subscription_started_still_active_event =
                    generate_job_subscription_started_log(None, Some(-50));

                let subscription_started_terminated_event =
                    generate_job_subscription_started_log(Some(2), Some(-2000));

                let subscription_job_params_updated_event =
                    generate_job_subscription_job_params_updated(
                        None,
                        Some("9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e7d8"),
                        Some(108),
                    );

                let system_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let subscription_termination_params_updated_event =
                    generate_job_subscription_termination_params_updated(
                        None,
                        Some(system_time + 1500),
                    );

                let subscription_started_still_active_event_2 =
                    generate_job_subscription_started_log(Some(3), None);

                Ok(vec![
                    subscription_started_still_active_event,
                    subscription_started_terminated_event,
                    subscription_job_params_updated_event,
                    subscription_termination_params_updated_event,
                    subscription_started_still_active_event_2,
                ])
            } else {
                return Err(ServerlessError::InvalidTopic);
            }
        } else {
            return Err(ServerlessError::EmptyTopics);
        }
    }
}

#[cfg(test)]
pub fn generate_job_subscription_started_log(
    job_id: Option<u64>,
    starttime_delta: Option<i64>,
) -> Log {
    let job_id = U256::from(job_id.unwrap_or(1));

    let starttime = U256::from(
        ((SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()) as i64
            + starttime_delta.unwrap_or(0)) as u64,
    );

    let termination_time = starttime + U256::from(1000);

    Log {
        inner: InnerLog {
            address: Address::default(),
            data: LogData::new_unchecked(
                vec![
                    keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT).into(),
                    job_id.into(),
                    U256::from(1).into(),
                    Address::from_str(SUBSCRIPTION_RELAY_CONTRACT_ADDR)
                        .unwrap()
                        .into_word(),
                ],
                DynSolValue::Tuple(vec![
                    DynSolValue::Uint(U256::from(10), 256),
                    DynSolValue::Uint(U256::from(1000), 256),
                    DynSolValue::Uint(termination_time, 256),
                    DynSolValue::Uint(U256::from(100), 256),
                    DynSolValue::Address(PrivateKeySigner::random().address()),
                    DynSolValue::FixedBytes(*CODE_HASH, 32),
                    DynSolValue::Bytes(
                        serde_json::to_vec(&json!({
                                "num": 10
                        }))
                        .unwrap(),
                    ),
                    DynSolValue::Uint(starttime, 256),
                ])
                .abi_encode()
                .as_slice()[32..]
                    .to_vec()
                    .into(),
            ),
        },
        ..Default::default()
    }
}

#[cfg(test)]
pub fn generate_generic_subscription_job(
    job_id: Option<u64>,
    starttime_delta: Option<i64>,
) -> SubscriptionJob {
    let starttime = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + starttime_delta.unwrap_or(0)) as u64;

    let termination_time = starttime + 1000;

    SubscriptionJob {
        subscription_id: U256::from(job_id.unwrap_or(1)),
        request_chain_id: CHAIN_ID,
        subscriber: Address::from_str(SUBSCRIPTION_RELAY_CONTRACT_ADDR).unwrap(),
        interval: 10,
        termination_time,
        user_timeout: U256::from(100),
        tx_hash: *CODE_HASH,
        code_input: serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into(),
        starttime,
        env: 1u8,
    }
}

#[cfg(test)]
pub fn generate_job_subscription_job_params_updated(
    job_id: Option<u64>,
    code_hash: Option<&str>,
    data_num: Option<u64>,
) -> Log {
    let code_hash_bytes;
    if code_hash.is_none() {
        code_hash_bytes = *CODE_HASH;
    } else {
        code_hash_bytes = keccak256(code_hash.unwrap());
    }

    Log {
        inner: InnerLog {
            address: Address::default(),
            data: LogData::new_unchecked(
                vec![
                    keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT).into(),
                    U256::from(job_id.unwrap_or(1)).into(),
                ],
                DynSolValue::Tuple(vec![
                    DynSolValue::FixedBytes(code_hash_bytes, 32),
                    DynSolValue::Bytes(
                        serde_json::to_vec(&json!({
                            "num": data_num.unwrap_or(10)
                        }))
                        .unwrap(),
                    ),
                ])
                .abi_encode()
                .as_slice()[32..]
                    .to_vec()
                    .into(),
            ),
        },
        ..Default::default()
    }
}

#[cfg(test)]
pub fn generate_job_subscription_termination_params_updated(
    job_id: Option<u64>,
    termination_time: Option<u64>,
) -> Log {
    let job_id = U256::from(job_id.unwrap_or(1));

    let termination_time = U256::from(
        termination_time.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 1000,
        ),
    );

    Log {
        inner: InnerLog {
            address: Address::default(),
            data: LogData::new_unchecked(
                vec![
                    keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT)
                        .into(),
                    job_id.into(),
                ],
                DynSolValue::Tuple(vec![DynSolValue::Uint(termination_time, 256)])
                    .abi_encode()
                    .into(),
            ),
        },
        ..Default::default()
    }
}
