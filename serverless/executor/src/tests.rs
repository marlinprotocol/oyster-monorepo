// NOTE: Tests have to be run one by one currently

/* To run an unit test 'test_name', hit the following commands on terminal ->
   1.    sudo ../executor-enclave/cgroupv2_setup.sh
   2.    export RUSTFLAGS="--cfg tokio_unstable"
   3.    sudo echo && cargo test 'test name' -- --nocapture &
   4.    sudo echo && cargo test -- --test-threads 1 &           (For running all the tests sequentially)
*/

#[cfg(test)]
pub mod serverless_executor_test {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::pin::pin;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, RwLock};

    use alloy::dyn_abi::DynSolValue;
    use alloy::hex;
    use alloy::primitives::{keccak256, Address, Bytes, LogData, B256, U256};
    use alloy::rpc::types::Log;
    use alloy::signers::k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::utils::public_key_to_address;
    use alloy::sol_types::SolEvent;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use axum_test::TestServer;
    use serde_json::{json, Value};
    use tempfile::Builder;
    use tokio::runtime::Handle;
    use tokio::sync::mpsc::channel;
    use tokio::time::{sleep, Duration};
    use tokio_stream::StreamExt as _;

    use crate::cgroups::Cgroups;
    use crate::constant::{EXECUTION_ENV_ID, MAX_OUTPUT_BYTES_LENGTH};
    use crate::events::handle_event_logs;
    use crate::model::{
        AppState, JobsContract, JobsTransaction, RegistrationMessage, TeeManagerContract,
    };
    use crate::server::{
        export_signed_registration_message, get_tee_details, index, inject_immutable_config,
        inject_mutable_config,
    };
    use crate::utils::get_byte_slice;

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arb-sepolia.g.alchemy.com/v2/";
    const TEE_MANAGER_CONTRACT_ADDR: &str = "0xFbc9cB063848Db801B382A1Da13E5A213dD378c0";
    const JOBS_CONTRACT_ADDR: &str = "0xb01AB6c250654978be77CD1098E5e760eC207b4F";
    const CODE_CONTRACT_ADDR: &str = "0xE10F9D50eDEef610888e75fA4BC82f8dA14167B2";

    // Generate test app state
    async fn generate_app_state(code_contract_uppercase: bool) -> AppState {
        let signer = PrivateKeySigner::random();

        AppState {
            job_capacity: 20,
            cgroups: Arc::new(Mutex::new(Cgroups::new().unwrap())),
            secret_store_config_port: 6002,
            workerd_runtime_path: "./runtime/".to_owned(),
            secret_store_path: "../store".to_owned(),
            execution_buffer_time: 10,
            common_chain_id: CHAIN_ID,
            http_rpc_url: HTTP_RPC_URL.to_owned(),
            ws_rpc_url: Arc::new(RwLock::new(WS_URL.to_owned())),
            tee_manager_contract_addr: TEE_MANAGER_CONTRACT_ADDR.parse::<Address>().unwrap(),
            jobs_contract_addr: JOBS_CONTRACT_ADDR.parse::<Address>().unwrap(),
            code_contract_addr: if code_contract_uppercase {
                CODE_CONTRACT_ADDR.to_uppercase()
            } else {
                CODE_CONTRACT_ADDR.to_owned()
            },
            num_selected_executors: 1,
            enclave_signer: signer,
            immutable_params_injected: Arc::new(Mutex::new(false)),
            mutable_params_injected: Arc::new(Mutex::new(false)),
            enclave_registered: Arc::new(AtomicBool::new(false)),
            events_listener_active: Arc::new(Mutex::new(false)),
            enclave_draining: Arc::new(AtomicBool::new(false)),
            enclave_owner: Arc::new(Mutex::new(Address::ZERO)),
            http_rpc_txn_manager: Arc::new(Mutex::new(None)),
            job_requests_running: Arc::new(Mutex::new(HashSet::new())),
            last_block_seen: Arc::new(AtomicU64::new(0)),
        }
    }

    // Return the Router app with the provided app state
    fn new_app(app_data: AppState) -> Router<()> {
        Router::new()
            .route("/", get(index))
            .route("/immutable-config", post(inject_immutable_config))
            .route("/mutable-config", post(inject_mutable_config))
            .route("/tee-details", get(get_tee_details))
            .route(
                "/signed-registration-message",
                get(export_signed_registration_message),
            )
            .with_state(app_data)
    }

    // TODO: add test attribute
    // Test the various response cases for the 'inject_immutable_config' endpoint
    #[tokio::test]
    async fn inject_immutable_config_test() {
        let app_state = generate_app_state(false).await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Inject invalid owner address hex string (odd length)
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": "32255",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Invalid owner address hex string: OddLength\n");

        // Inject invalid owner address hex string (invalid hex character)
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": "0x32255G",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Invalid owner address hex string: InvalidHexCharacter { c: 'G', index: 5 }\n",
        );

        // Inject invalid owner address hex string (less than 20 bytes)
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": "0x322557",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Owner address must be 20 bytes long!\n");

        // Mock secret store immutable configuration endpoint
        let (mock_params, mock_state) =
            mock_post_endpoint(app_state.secret_store_config_port, "/immutable-config").await;

        // Inject valid immutable config params
        {
            let mut state = mock_state.lock().unwrap();
            *state = (
                StatusCode::OK,
                String::from("Immutable params configured!\n"),
            );
        }
        let valid_owner = Address::from([0x42; 20]);
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("owner_address_hex") {
            assert_eq!(actual, &hex::encode(valid_owner));
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'owner_address_hex'"
            );
        }

        // Inject valid immutable config params again to test immutability
        {
            let mut state = mock_state.lock().unwrap();
            *state = (
                StatusCode::BAD_REQUEST,
                String::from("Immutable params already configured!\n"),
            );
        }
        let valid_owner_2 = Address::from([0x11; 20]);
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": hex::encode(valid_owner_2),
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Failed to inject immutable config into the secret store: Immutable params already configured!\n");
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("owner_address_hex") {
            assert_eq!(actual, &hex::encode(valid_owner_2));
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'owner_address_hex'"
            );
        }
    }

    #[tokio::test]
    // Test the various response cases for the 'inject_mutable_config' endpoint
    async fn inject_mutable_config_test() {
        let app_state = generate_app_state(false).await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Inject invalid executor gas private key hex string (less than 32 bytes)
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": "0x322557",
                "secret_store_gas_key": "",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Failed to hex decode the gas private key into 32 bytes: InvalidStringLength\n",
        );

        // Inject invalid executor gas private key hex string (invalid hex character)
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": "fffffffffffffffffzffffffffffffffffffffffffffffgfffffffffffffffff",
                "secret_store_gas_key": "",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Failed to hex decode the gas private key into 32 bytes: InvalidHexCharacter { c: 'z', index: 17 }\n",
        );

        // Inject invalid executor gas private key hex string (not ecdsa valid key)
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "secret_store_gas_key": "",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Invalid gas private key provided: signature::Error { source: None }\n");

        // Initialise executor gas wallet key
        let executor_gas_wallet_key = PrivateKeySigner::random();

        // Inject invalid ws_api_key hex string with invalid character
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": "",
                "ws_api_key": "&&&&",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("API key contains invalid characters!\n");

        // Mock secret store mutable configuration endpoint
        let (mock_params, mock_state) =
            mock_post_endpoint(app_state.secret_store_config_port, "/mutable-config").await;

        // Inject invalid secret store gas private key hex string (invalid hex character)
        {
            let mut state = mock_state.lock().unwrap();
            *state = (StatusCode::BAD_REQUEST, String::from("Failed to hex decode the gas private key into 32 bytes: InvalidHexCharacter { c: 'z', index: 17 }\n"));
        }

        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": "fffffffffffffffffzffffffffffffffffffffffffffffgfffffffffffffffff",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Failed to inject mutable config into the secret store: Failed to hex decode the gas private key into 32 bytes: InvalidHexCharacter { c: 'z', index: 17 }\n");
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("gas_key_hex") {
            assert_eq!(
                actual,
                "fffffffffffffffffzffffffffffffffffffffffffffffgfffffffffffffffff"
            );
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'gas_key_hex'"
            );
        }
        if let Some(Value::String(actual)) = secret_store_param.get("ws_api_key") {
            assert_eq!(actual, "ws_api_key");
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'ws_api_key'"
            );
        }

        // Inject invalid secret store gas private key hex string (not ecdsa valid key)
        {
            let mut state = mock_state.lock().unwrap();
            *state = (StatusCode::BAD_REQUEST, String::from("Invalid gas private key provided: EcdsaError(signature::Error { source: None })\n"));
        }

        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Failed to inject mutable config into the secret store: Invalid gas private key provided: EcdsaError(signature::Error { source: None })\n");
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("gas_key_hex") {
            assert_eq!(
                actual,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            );
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'gas_key_hex'"
            );
        }
        if let Some(Value::String(actual)) = secret_store_param.get("ws_api_key") {
            assert_eq!(actual, "ws_api_key");
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'ws_api_key'"
            );
        }

        // Inject valid mutable config params
        {
            let mut state = mock_state.lock().unwrap();
            *state = (StatusCode::OK, String::from("Mutable params configured!\n"));
        }
        let secret_store_gas_wallet_key = PrivateKeySigner::random();

        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": hex::encode(secret_store_gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(executor_gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.ws_rpc_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("gas_key_hex") {
            assert_eq!(actual, &hex::encode(secret_store_gas_wallet_key.to_bytes()));
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'gas_key_hex'"
            );
        }
        if let Some(Value::String(actual)) = secret_store_param.get("ws_api_key") {
            assert_eq!(actual, "ws_api_key");
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'ws_api_key'"
            );
        }

        // Inject valid mutable config params again to test mutability
        let executor_gas_wallet_key = PrivateKeySigner::random();
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": hex::encode(secret_store_gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key_2",
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(executor_gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.ws_rpc_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key_2"
        );
        let secret_store_param = mock_params.lock().unwrap().clone();
        if let Some(Value::String(actual)) = secret_store_param.get("gas_key_hex") {
            assert_eq!(actual, &hex::encode(secret_store_gas_wallet_key.to_bytes()));
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'gas_key_hex'"
            );
        }
        if let Some(Value::String(actual)) = secret_store_param.get("ws_api_key") {
            assert_eq!(actual, "ws_api_key_2");
        } else {
            assert!(
                false,
                "Failed to get secret store endpoint parameter 'ws_api_key'"
            );
        }
    }

    #[tokio::test]
    // Test the various response cases for the 'get_tee_details' endpoint
    async fn get_tee_details_test() {
        let app_state = generate_app_state(false).await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Mock secret store details endpoint
        let mock_state =
            mock_get_endpoint(app_state.secret_store_config_port, "/store-details").await;

        // Get the tee details without injecting any config params
        {
            // Mock secret store response
            let mut state = mock_state.lock().unwrap();
            *state = (
                StatusCode::OK,
                json!({
                    "enclave_address": app_state.enclave_signer.address(),
                    "enclave_public_key": format!(
                        "0x{}",
                        hex::encode(
                            &(app_state
                                .enclave_signer
                                .credential()
                                .verifying_key()
                                .to_encoded_point(false)
                                .as_bytes())[1..]
                        )
                    ),
                    "owner_address": Address::ZERO,
                    "gas_address": Address::ZERO,
                    "ws_rpc_url": WS_URL,
                }),
            );
        }
        let resp = server.get("/tee-details").await;

        resp.assert_status_ok();
        resp.assert_json(&json!({
            "enclave_address": app_state.enclave_signer.address(),
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": Address::ZERO,
            "executor_gas_address": Address::ZERO,
            "secret_store_gas_address": Address::ZERO,
            "ws_rpc_url": WS_URL,
        }));

        // Inject valid immutable config params
        let valid_owner = Address::from([0x42; 20]);
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);

        // Get the executor details without injecting mutable config params
        let resp = server.get("/tee-details").await;

        resp.assert_status_ok();
        resp.assert_json(&json!({
            "enclave_address": app_state.enclave_signer.address(),
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": valid_owner,
            "executor_gas_address": Address::ZERO,
            "secret_store_gas_address": Address::ZERO,
            "ws_rpc_url": WS_URL,
        }));

        // Inject valid mutable config params
        let executor_gas_wallet_key = PrivateKeySigner::random();
        let secret_store_gas_wallet_key = PrivateKeySigner::random();
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": hex::encode(secret_store_gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(executor_gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.ws_rpc_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );

        // Get the executor details
        {
            // Mock secret store response after injecting configs
            let mut state = mock_state.lock().unwrap();
            *state = (
                StatusCode::OK,
                json!({
                    "enclave_address": app_state.enclave_signer.address(),
                    "enclave_public_key": format!(
                        "0x{}",
                        hex::encode(
                            &(app_state
                                .enclave_signer
                                .credential()
                                .verifying_key()
                                .to_encoded_point(false)
                                .as_bytes())[1..]
                        )
                    ),
                    "owner_address": valid_owner,
                    "gas_address": public_key_to_address(secret_store_gas_wallet_key.credential().verifying_key()),
                    "ws_rpc_url": WS_URL,
                }),
            );
        }
        let resp = server.get("/tee-details").await;

        resp.assert_status_ok();
        resp.assert_json(&json!({
            "enclave_address": app_state.enclave_signer.address(),
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": valid_owner,
            "executor_gas_address": public_key_to_address(executor_gas_wallet_key.credential().verifying_key()),
            "secret_store_gas_address": public_key_to_address(secret_store_gas_wallet_key.credential().verifying_key()),
            "ws_rpc_url": WS_URL.to_owned() + "ws_api_key",
        }));
    }

    #[tokio::test]
    // Test the various response cases for the 'export_signed_registration_message' endpoint
    async fn export_signed_registration_message_test() {
        let metrics = Handle::current().metrics();

        let app_state = generate_app_state(false).await;
        let verifying_key = app_state
            .enclave_signer
            .credential()
            .verifying_key()
            .to_owned();

        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Mock secret store register details endpoint
        let mock_state =
            mock_get_endpoint(app_state.secret_store_config_port, "/register-details").await;

        // Export the enclave registration details without injecting tee config params
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_bad_request();
        resp.assert_text("Immutable params not configured yet!\n");

        // Inject valid immutable config params
        let valid_owner = Address::from([0x42; 20]);
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);

        // Export the enclave registration details without injecting mutable config params
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_bad_request();
        resp.assert_text("Mutable params not configured yet!\n");

        // Inject valid mutable config params
        let executor_gas_wallet_key = PrivateKeySigner::random();
        let secret_store_gas_wallet_key = PrivateKeySigner::random();
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": hex::encode(executor_gas_wallet_key.to_bytes()),
                "secret_store_gas_key": hex::encode(secret_store_gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(executor_gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.ws_rpc_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );

        // Export the enclave registration details
        const STORAGE_CAPACITY: usize = 100000;
        {
            // Mock secret store response
            let mut state = mock_state.lock().unwrap();
            *state = (
                StatusCode::OK,
                json!({
                    "storage_capacity": STORAGE_CAPACITY,
                }),
            );
        }
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_ok();

        let response: Result<RegistrationMessage, serde_json::Error> =
            serde_json::from_slice(&resp.as_bytes());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.job_capacity, 20);
        assert_eq!(response.storage_capacity, STORAGE_CAPACITY);
        assert_eq!(response.owner, valid_owner);
        assert_eq!(response.env, 1);
        assert_eq!(response.signature.len(), 132);
        assert_eq!(
            recover_key(
                response.owner,
                response.job_capacity,
                response.storage_capacity,
                response.sign_timestamp as usize,
                response.signature
            ),
            verifying_key
        );
        assert_eq!(*app_state.events_listener_active.lock().unwrap(), true);
        let active_tasks = metrics.num_alive_tasks();

        // Export the enclave registration details again
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_ok();

        let response: Result<RegistrationMessage, serde_json::Error> =
            serde_json::from_slice(&resp.as_bytes());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.job_capacity, 20);
        assert_eq!(response.owner, valid_owner);
        assert_eq!(response.signature.len(), 132);
        assert_eq!(
            recover_key(
                response.owner,
                response.job_capacity,
                response.storage_capacity,
                response.sign_timestamp as usize,
                response.signature
            ),
            verifying_key
        );
        assert_eq!(active_tasks, metrics.num_alive_tasks());
    }

    #[tokio::test]
    // Test a valid job request with different inputs and verify the responses
    async fn valid_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "92405e4b971ae2e59a592facbfc23a59fae378d0049b9b588da420b4c888c712";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        // Prepare the logs for JobCreated and JobResponded events accordingly
        let mut jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 20
        }))
        .unwrap()
        .into();

        jobs_created_logs.push(get_job_created_log(
            1,
            U256::ONE,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        ));

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 600
        }))
        .unwrap()
        .into();

        jobs_created_logs.push(get_job_created_log(
            1,
            U256::from(2),
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        ));

        let jobs_responded_logs = vec![
            get_job_responded_log(1, U256::ZERO, app_state.enclave_signer.address()),
            get_job_responded_log(1, U256::ONE, app_state.enclave_signer.address()),
            get_job_responded_log(1, U256::from(2), app_state.enclave_signer.address()),
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            // Introduce time interval between events to be polled
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(user_deadline)).await;
                    log
                }
            ));
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 3);

        assert_response(responses[0].clone(), U256::ZERO, 0, "2,5".into());
        assert_response(responses[1].clone(), U256::ONE, 0, "2,2,5".into());
        assert_response(responses[2].clone(), U256::from(2), 0, "2,2,2,3,5,5".into());
    }

    #[tokio::test]
    // Test a valid job request with user code contract set in uppercase and verify the response
    async fn valid_job_test_with_uppercase_code_contract() {
        let app_state = generate_app_state(true).await;

        let code_hash = "92405e4b971ae2e59a592facbfc23a59fae378d0049b9b588da420b4c888c712";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];
        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 0, "2,5".into());
    }

    #[tokio::test]
    // Test a valid job request with invalid input and verify the response
    async fn invalid_input_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "92405e4b971ae2e59a592facbfc23a59fae378d0049b9b588da420b4c888c712";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];
        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            U256::ZERO,
            0,
            "Please provide a valid integer as input in the format{'num':10}".into(),
        );
    }

    #[tokio::test]
    // Test '1' error code job requests and verify the responses
    async fn invalid_transaction_job_test() {
        let app_state = generate_app_state(false).await;

        let user_deadline = 5000;
        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![
            // Given transaction hash doesn't belong to the expected smart contract
            get_job_created_log(
                1,
                U256::ZERO,
                U256::ZERO,
                EXECUTION_ENV_ID,
                "fed8ab36cc27831836f6dcb7291049158b4d8df31c0ffb05a3d36ba6555e29d7",
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_signer.address(),
            ),
            // Given transaction hash doesn't exist in the expected rpc network
            get_job_created_log(
                1,
                U256::ONE,
                U256::ZERO,
                EXECUTION_ENV_ID,
                "37b0b2d9dd58d9130781fc914da456c16ec403010e8d4c27b0ea4657a24c8546",
                code_input_bytes,
                user_deadline,
                app_state.enclave_signer.address(),
            ),
        ];

        let jobs_responded_logs = vec![
            get_job_responded_log(1, U256::ZERO, app_state.enclave_signer.address()),
            get_job_responded_log(1, U256::ONE, app_state.enclave_signer.address()),
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(user_deadline)).await;
                    log
                }
            ));
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 2);

        assert_response(responses[0].clone(), U256::ZERO, 1, "".into());
        assert_response(responses[1].clone(), U256::ONE, 1, "".into());
    }

    #[tokio::test]
    // Test '2' error code job request and verify the response
    async fn invalid_code_calldata_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "daa2d71f3a93cccca0c310520ba9fcb2f9402cd80de486725366ca10d95d2091";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Calldata corresponding to the provided transaction hash is invalid
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 2, "".into());
    }

    #[tokio::test]
    // Test '3' error code job request and verify the response
    async fn invalid_code_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "2d3f3bedf64177f85805982fe091f4b0855078228b51181e43cf81249136eb2b";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Code corresponding to the provided transaction hash has a syntax error
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 3, "".into());
    }

    #[tokio::test]
    // Test '4' error code job request and verify the response
    async fn deadline_timeout_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "f3f625a14c0680ec15e2418284fad9f8bef4c6cb231618088e0d7962d5c6341a";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code didn't return a response in the expected period
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 4, "".into());
    }

    #[tokio::test]
    // Test the execution timeout case where enough job responses are not received and slashing transaction should be sent for the job request
    async fn timeout_job_execution_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "f3f625a14c0680ec15e2418284fad9f8bef4c6cb231618088e0d7962d5c6341a";
        let user_deadline = 5000;
        let execution_buffer_time = app_state.execution_buffer_time;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Add log entry to relay a job but job response event is not sent and the executor doesn't execute the job request
        let jobs_created_logs = vec![
            get_job_created_log(
                1,
                U256::ZERO,
                U256::ZERO,
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes,
                user_deadline,
                Address::from([0x42; 20]),
            ),
            Log {
                ..Default::default()
            },
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(
                        user_deadline + execution_buffer_time * 1000 + 1000,
                    ))
                    .await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                pin!(tokio_stream::empty()),
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);
        let job_response = responses[0].clone();
        if let JobsTransaction::TIMEOUT(call) = job_response {
            assert_eq!(call._jobId, U256::ZERO);
        } else {
            assert!(false, "Job timeout response not received!");
        }
    }

    #[tokio::test]
    // Test ExecutorDeregistered event handling
    async fn executor_deregistered_test() {
        let app_state = generate_app_state(false).await;
        app_state.enclave_registered.store(true, Ordering::SeqCst);

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        // Add log for deregistering the current executor
        let log_data = LogData::new(
            vec![
                TeeManagerContract::TeeNodeDeregistered::SIGNATURE_HASH.into(),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            Bytes::new(),
        )
        .unwrap();
        let executor_deregistered_logs = vec![Log {
            inner: alloy::primitives::Log {
                address: Address::from_str(TEE_MANAGER_CONTRACT_ADDR).unwrap(),
                data: log_data,
            },
            removed: false,
            block_number: Some(1),
            ..Default::default()
        }];

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let executor_deregistered_stream =
                pin!(tokio_stream::iter(executor_deregistered_logs.into_iter())
                    .chain(tokio_stream::pending()));

            handle_event_logs(
                pin!(tokio_stream::pending()),
                pin!(tokio_stream::pending()),
                executor_deregistered_stream,
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        while rx.recv().await.is_some() {
            assert!(false, "Response received even after deregistration!");
        }

        assert!(
            !app_state_clone.enclave_registered.load(Ordering::SeqCst),
            "Enclave not set to deregistered in the app_state!"
        );
    }

    #[tokio::test]
    // Test different env ID job created event
    async fn invalid_env_id_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "92405e4b971ae2e59a592facbfc23a59fae378d0049b9b588da420b4c888c712";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        // Prepare the logs for JobCreated log for different env ID '2'
        let jobs_created_logs = vec![
            get_job_created_log(
                1,
                U256::ZERO,
                U256::ZERO,
                2,
                code_hash,
                code_input_bytes,
                user_deadline,
                app_state.enclave_signer.address(),
            ),
            Log {
                ..Default::default()
            },
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(user_deadline)).await;
                    log
                }
            ));

            handle_event_logs(
                jobs_created_stream,
                pin!(tokio_stream::empty()),
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        while rx.recv().await.is_some() {
            assert!(false, "Response received for different ENV ID!");
        }
    }

    #[tokio::test]
    // Test '5' error code, serverless output size exceeds the limit
    async fn output_size_too_large() {
        let app_state = generate_app_state(false).await;

        // This serverless code return bytes array of given length filled with zeros
        let code_hash = "7b12332d0271dd9bcdd7666017acad1e12b894d287cee1e1f17f4513c2a8cec3";
        let user_deadline = 5000;

        // Case 1: Output size is exceeds the limit
        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "len": MAX_OUTPUT_BYTES_LENGTH + 1
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 5, "".into());
    }

    #[tokio::test]
    //Test Output size is equals to the limit
    async fn output_size_limit_test() {
        let app_state = generate_app_state(false).await;

        // This serverless code return bytes array of given length filled with zeros
        let code_hash = "7b12332d0271dd9bcdd7666017acad1e12b894d287cee1e1f17f4513c2a8cec3";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "len": MAX_OUTPUT_BYTES_LENGTH
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }
        assert_eq!(responses.len(), 1);
        let expected_resp: Bytes = Bytes::from_static(&[0u8; MAX_OUTPUT_BYTES_LENGTH]);
        assert_response(responses[0].clone(), U256::ZERO, 0, expected_resp);
    }

    #[tokio::test]
    // Test job execution with secret Id
    async fn job_execution_with_secret_test() {
        let app_state = generate_app_state(false).await;

        // Create a temporary store directory inside the parent
        let temp_dir = Builder::new()
            .prefix("store")
            .rand_bytes(0)
            .tempdir_in("./")
            .expect("Failed to create temporary store directory");

        // Create a secret file with id 1
        let file_path = temp_dir.path().join("1.bin");
        std::fs::write(&file_path, "Secret!").expect("Failed to write to file ./store/1.bin");
        // Create a secret file with id 2
        let file_path_2 = temp_dir.path().join("2.bin");
        std::fs::write(&file_path_2, "Oyster123!").expect("Failed to write to file ./store/2.bin");

        let code_hash = "f88ac0e686d753d23618827bf01a079fa5de68a76347f3b26b91dbfba9710401";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code returning a string containing the secret data
        let jobs_created_logs = vec![
            get_job_created_log(
                1,
                U256::ZERO,
                U256::ONE,
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_signer.address(),
            ),
            get_job_created_log(
                1,
                U256::ONE,
                U256::from(2),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes,
                user_deadline,
                app_state.enclave_signer.address(),
            ),
        ];

        let jobs_responded_logs = vec![
            get_job_responded_log(1, U256::ZERO, app_state.enclave_signer.address()),
            get_job_responded_log(1, U256::ONE, app_state.enclave_signer.address()),
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            // Introduce time interval between events to be polled
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(user_deadline)).await;
                    log
                }
            ));

            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 2);

        assert_response(
            responses[0].clone(),
            U256::ZERO,
            0,
            "Hello World my secret is Secret!".into(),
        );
        assert_response(
            responses[1].clone(),
            U256::ONE,
            0,
            "Hello World my secret is Oyster123!".into(),
        );
    }

    #[tokio::test]
    // Test job execution with secret Id failing user deadline
    async fn job_execution_with_secret_timeout_test() {
        let app_state = generate_app_state(false).await;

        // Create a temporary store directory inside the parent
        let temp_dir = Builder::new()
            .prefix("store")
            .rand_bytes(0)
            .tempdir_in("./")
            .expect("Failed to create temporary store directory");

        // Create a secret file with id 1
        let file_path = temp_dir.path().join("1.bin");
        std::fs::write(&file_path, "Secret!").expect("Failed to write to file ./store/1.bin");

        let code_hash = "91c686c4569fa8999faf0aae5a2b3d68287265288c6bd9bfe1ff08959c2e9def";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code returning a string containing the secret data after 10 secs delay
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ONE,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 4, "".into());
    }

    #[tokio::test]
    // Test code execution that overflows stack size
    async fn job_execution_stack_overflow_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "d7d2cdd23f081b994fbf792a1f37ae64a7c499ddb8c6398cb89f927aa5536046";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code invokes deep recursion
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            U256::ZERO,
            0,
            "Internal Server Error".into(),
        );
    }

    #[tokio::test]
    // Test code execution that bloats heap size
    async fn job_execution_heap_bloat_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "40f5a4f624e7aad1a816dc50db7ae9600c1de1e436b39c70e18d23159279d247";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code invokes excessive heap allocation
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 1000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(jobs_created_logs)),
                jobs_responded_stream,
                pin!(tokio_stream::empty()),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            U256::ZERO,
            0,
            "Internal Server Error".into(),
        );
    }

    #[tokio::test]
    // Test the executor draining case by sending job request after draining and not sending response log
    async fn executor_drain_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "f3f625a14c0680ec15e2418284fad9f8bef4c6cb231618088e0d7962d5c6341a";
        let user_deadline = 5000;
        let execution_buffer_time = app_state.execution_buffer_time;
        let app_state_clone = app_state.clone();

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Add drain log for the executor
        let log_data = LogData::new(
            vec![
                TeeManagerContract::TeeNodeDrained::SIGNATURE_HASH.into(),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            Bytes::new(),
        )
        .unwrap();
        let executor_drain_logs = vec![Log {
            inner: alloy::primitives::Log {
                address: Address::from_str(TEE_MANAGER_CONTRACT_ADDR).unwrap(),
                data: log_data,
            },
            removed: false,
            block_number: Some(1),
            ..Default::default()
        }];

        // Add log entry to relay a job but job response event is not sent
        let jobs_created_logs = vec![
            get_job_created_log(
                1,
                U256::ZERO,
                U256::ZERO,
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes,
                user_deadline,
                app_state.enclave_signer.address(),
            ),
            Log {
                ..Default::default()
            },
        ];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(
                        user_deadline + execution_buffer_time * 1000 + 1000,
                    ))
                    .await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                pin!(tokio_stream::empty()),
                pin!(tokio_stream::iter(executor_drain_logs.into_iter())),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        while rx.recv().await.is_some() {
            assert!(false, "Response received even after draining!");
        }

        assert!(
            app_state_clone.enclave_draining.load(Ordering::SeqCst),
            "Executor not set to draining in the app_state!"
        );
    }

    #[tokio::test]
    // Test the executor reviving case by sending job request after reviving from drain
    async fn executor_revive_test() {
        let app_state = generate_app_state(false).await;
        app_state.enclave_draining.store(true, Ordering::SeqCst);

        let code_hash = "f3f625a14c0680ec15e2418284fad9f8bef4c6cb231618088e0d7962d5c6341a";
        let user_deadline = 5000;
        let app_state_clone = app_state.clone();

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Add revive log for the executor
        let log_data = LogData::new(
            vec![
                TeeManagerContract::TeeNodeRevived::SIGNATURE_HASH.into(),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            Bytes::new(),
        )
        .unwrap();
        let executor_revive_logs = vec![Log {
            inner: alloy::primitives::Log {
                address: Address::from_str(TEE_MANAGER_CONTRACT_ADDR).unwrap(),
                data: log_data,
            },
            removed: false,
            block_number: Some(1),
            ..Default::default()
        }];

        // Add log entry to relay a job
        let jobs_created_logs = vec![get_job_created_log(
            1,
            U256::ZERO,
            U256::ZERO,
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_signer.address(),
        )];

        let jobs_responded_logs = vec![get_job_responded_log(
            1,
            U256::ZERO,
            app_state.enclave_signer.address(),
        )];

        let (tx, mut rx) = channel::<JobsTransaction>(10);

        tokio::spawn(async move {
            let jobs_created_stream = pin!(tokio_stream::iter(jobs_created_logs.into_iter()).then(
                |log| async move {
                    sleep(Duration::from_millis(1000)).await;
                    log
                }
            ));

            let jobs_responded_stream = pin!(tokio_stream::iter(jobs_responded_logs.into_iter())
                .then(|log| async move {
                    sleep(Duration::from_millis(user_deadline + 2000)).await;
                    log
                }));

            // Call the event handler for the contract logs
            handle_event_logs(
                jobs_created_stream,
                jobs_responded_stream,
                pin!(tokio_stream::iter(executor_revive_logs.into_iter())),
                State {
                    0: app_state.clone(),
                },
                tx,
            )
            .await;
        });

        let mut responses: Vec<JobsTransaction> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), U256::ZERO, 4, "".into());
        assert!(
            !app_state_clone.enclave_draining.load(Ordering::SeqCst),
            "Executor still draining in the app_state!"
        );
    }

    fn get_job_created_log(
        block_number: u64,
        job_id: U256,
        secret_id: U256,
        env_id: u8,
        code_hash: &str,
        code_inputs: Bytes,
        user_deadline: u64,
        enclave: Address,
    ) -> Log {
        let log_data = LogData::new(
            vec![
                JobsContract::JobCreated::SIGNATURE_HASH.into(),
                B256::from(job_id),
                B256::from(&get_byte_slice(env_id)),
                B256::from(Address::from(&[0x11; 20]).into_word()),
            ],
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::FixedBytes(B256::from_slice(&hex::decode(code_hash).unwrap()), 32),
                DynSolValue::Bytes(code_inputs.to_vec()),
                DynSolValue::Uint(U256::from(user_deadline), 256),
                DynSolValue::Array(vec![DynSolValue::Address(enclave)]),
            ])
            .abi_encode_sequence()
            .unwrap()
            .into(),
        )
        .unwrap();

        Log {
            block_number: Some(block_number),
            inner: alloy::primitives::Log {
                address: Address::from_str(JOBS_CONTRACT_ADDR).unwrap(),
                data: log_data,
            },
            removed: false,
            ..Default::default()
        }
    }

    fn get_job_responded_log(block_number: u64, job_id: U256, enclave: Address) -> Log {
        let log_data = LogData::new(
            vec![
                JobsContract::JobResponded::SIGNATURE_HASH.into(),
                B256::from(job_id),
                B256::from(enclave.into_word()),
            ],
            DynSolValue::Tuple(vec![
                DynSolValue::Bytes([].into()),
                DynSolValue::Uint(U256::ONE, 256),
                DynSolValue::Uint(U256::ZERO, 8),
                DynSolValue::Uint(U256::ONE, 8),
            ])
            .abi_encode_sequence()
            .unwrap()
            .into(),
        )
        .unwrap();

        Log {
            block_number: Some(block_number),
            inner: alloy::primitives::Log {
                address: Address::from_str(JOBS_CONTRACT_ADDR).unwrap(),
                data: log_data,
            },
            removed: false,
            ..Default::default()
        }
    }

    async fn mock_post_endpoint(
        port: u16,
        endpoint: &str,
    ) -> (Arc<Mutex<Value>>, Arc<Mutex<(StatusCode, String)>>) {
        let shared_state = Arc::new(Mutex::new((StatusCode::OK, String::new())));
        let captured_params: Arc<Mutex<Value>> = Arc::new(Mutex::new(json!({})));

        let state_clone = shared_state.clone();
        let captured_params_clone = captured_params.clone();
        let app = Router::new().route(
            endpoint,
            post(move |Json(payload): Json<Value>| {
                let state = state_clone;
                let handler_state = captured_params_clone;

                async move {
                    let (status_code, response_body) = &*state.lock().unwrap();
                    *handler_state.lock().unwrap() = payload;

                    (status_code.clone(), response_body.clone()).into_response()
                }
            }),
        );

        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = axum::Server::bind(&addr).serve(app.into_make_service());

        tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("Server error: {}", err);
            }
        });

        (captured_params, shared_state)
    }

    async fn mock_get_endpoint(port: u16, endpoint: &str) -> Arc<Mutex<(StatusCode, Value)>> {
        let shared_state = Arc::new(Mutex::new((StatusCode::OK, json!({}))));

        let state_clone = shared_state.clone();
        let app = Router::new()
            .route(
                endpoint,
                get(move || {
                    let state = state_clone;

                    async move {
                        let (status_code, response_body) = &*state.lock().unwrap();

                        (status_code.clone(), Json(response_body.clone())).into_response()
                    }
                }),
            )
            .route(
                "/immutable-config",
                post(move || async move {
                    (StatusCode::OK, format!("Immutable params configured!\n")).into_response()
                }),
            )
            .route(
                "/mutable-config",
                post(move || async move {
                    (StatusCode::OK, format!("Mutable params configured!\n")).into_response()
                }),
            );

        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = axum::Server::bind(&addr).serve(app.into_make_service());

        tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("Server error: {}", err);
            }
        });

        shared_state
    }

    fn recover_key(
        owner: Address,
        job_capacity: usize,
        storage_capacity: usize,
        sign_timestamp: usize,
        sign: String,
    ) -> VerifyingKey {
        // Regenerate the digest for verification
        let domain_separator = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
                DynSolValue::FixedBytes(keccak256("marlin.oyster.TeeManager"), 32),
                DynSolValue::FixedBytes(keccak256("1"), 32),
            ])
            .abi_encode(),
        );
        let register_typehash = keccak256(
            "Register(address owner,uint256 jobCapacity,uint256 storageCapacity,uint8 env,uint256 signTimestamp)",
        );

        let hash_struct = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(register_typehash, 32),
                DynSolValue::Address(owner),
                DynSolValue::Uint(U256::from(job_capacity), 256),
                DynSolValue::Uint(U256::from(storage_capacity), 256),
                DynSolValue::Uint(U256::from(EXECUTION_ENV_ID), 256),
                DynSolValue::Uint(U256::from(sign_timestamp), 256),
            ])
            .abi_encode(),
        );
        let digest = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::String("\x19\x01".to_string()),
                DynSolValue::FixedBytes(domain_separator, 32),
                DynSolValue::FixedBytes(hash_struct, 32),
            ])
            .abi_encode_packed(),
        );

        let signature =
            Signature::from_slice(hex::decode(&sign[2..130]).unwrap().as_slice()).unwrap();
        let v = RecoveryId::try_from((hex::decode(&sign[130..]).unwrap()[0]) - 27).unwrap();
        let recovered_key =
            VerifyingKey::recover_from_prehash(&digest.to_vec(), &signature, v).unwrap();

        return recovered_key;
    }

    fn assert_response(job_response: JobsTransaction, id: U256, error: u8, output: Bytes) {
        if let JobsTransaction::OUTPUT(call, _) = job_response {
            assert_eq!(call._jobId, id);
            assert_eq!(call._errorCode, error);
            assert_eq!(call._output, output);
        } else {
            assert!(false, "Job output not received");
        }
    }
}
