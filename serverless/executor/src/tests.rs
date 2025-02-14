// NOTE: Tests have to be run one by one currently

/* To run an unit test 'test_name', hit the following commands on terminal ->
   1.    sudo ./cgroupv2_setup.sh
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

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use axum_test::TestServer;
    use bytes::Bytes;
    use ethers::abi::{encode, encode_packed, Token};
    use ethers::types::{Address, BigEndianHash, Log, H160, H256, U256, U64};
    use ethers::utils::{keccak256, public_key_to_address};
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tempfile::Builder;
    use tokio::runtime::Handle;
    use tokio::sync::mpsc::channel;
    use tokio::time::{sleep, Duration};
    use tokio_stream::StreamExt as _;

    use crate::cgroups::Cgroups;
    use crate::constant::{EXECUTION_ENV_ID, MAX_OUTPUT_BYTES_LENGTH};
    use crate::event_handler::handle_event_logs;
    use crate::model::{AppState, JobsTxnMetadata, JobsTxnType};
    use crate::node_handler::{
        export_signed_registration_message, get_tee_details, index, inject_immutable_config,
        inject_mutable_config,
    };
    use crate::utils::load_abi_from_file;

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arb-sepolia.g.alchemy.com/v2/";
    const TEE_MANAGER_CONTRACT_ADDR: &str = "0xFbc9cB063848Db801B382A1Da13E5A213dD378c0";
    const JOBS_CONTRACT_ADDR: &str = "0xb01AB6c250654978be77CD1098E5e760eC207b4F";
    const CODE_CONTRACT_ADDR: &str = "0x44fe06d2940b8782a0a9a9ffd09c65852c0156b1";

    // Generate test app state
    async fn generate_app_state(code_contract_uppercase: bool) -> AppState {
        let signer = SigningKey::random(&mut OsRng);
        let signer_verifier_address = public_key_to_address(signer.verifying_key());

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
            enclave_address: signer_verifier_address,
            enclave_signer: signer,
            immutable_params_injected: Arc::new(Mutex::new(false)),
            mutable_params_injected: Arc::new(Mutex::new(false)),
            enclave_registered: Arc::new(AtomicBool::new(false)),
            events_listener_active: Arc::new(Mutex::new(false)),
            enclave_owner: Arc::new(Mutex::new(H160::zero())),
            http_rpc_client: Arc::new(Mutex::new(None)),
            job_requests_running: Arc::new(Mutex::new(HashSet::new())),
            last_block_seen: Arc::new(AtomicU64::new(0)),
            nonce_to_send: Arc::new(Mutex::new(U256::from(0))),
            jobs_contract_abi: load_abi_from_file().unwrap(),
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
                "owner_address_hex": "32255G",
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
                "owner_address_hex": "322557",
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
        let valid_owner = H160::random();
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
        let valid_owner_2 = H160::random();
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
                "executor_gas_key": "322557",
                "secret_store_gas_key": "",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Gas private key must be 32 bytes long!\n");

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
            "Invalid gas private key hex string: InvalidHexCharacter { c: 'z', index: 17 }\n",
        );

        // Inject invalid executor gas private key hex string (not ecdsa valid key)
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "executor_gas_key": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "secret_store_gas_key": "",
                "ws_api_key": "ws_api_key",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Invalid gas private key provided: EcdsaError(signature::Error { source: None })\n",
        );

        // Initialise executor gas wallet key
        let executor_gas_wallet_key = SigningKey::random(&mut OsRng);

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
        let secret_store_gas_wallet_key = SigningKey::random(&mut OsRng);

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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(executor_gas_wallet_key.verifying_key())
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
        let executor_gas_wallet_key = SigningKey::random(&mut OsRng);
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(executor_gas_wallet_key.verifying_key())
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
                    "enclave_address": app_state.enclave_address,
                    "enclave_public_key": format!(
                        "0x{}",
                        hex::encode(
                            &(app_state
                                .enclave_signer
                                .verifying_key()
                                .to_encoded_point(false)
                                .as_bytes())[1..]
                        )
                    ),
                    "owner_address": H160::zero(),
                    "gas_address": H160::zero(),
                    "ws_rpc_url": WS_URL,
                }),
            );
        }
        let resp = server.get("/tee-details").await;

        resp.assert_status_ok();
        resp.assert_json(&json!({
            "enclave_address": app_state.enclave_address,
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": H160::zero(),
            "executor_gas_address": H160::zero(),
            "secret_store_gas_address": H160::zero(),
            "ws_rpc_url": WS_URL,
        }));

        // Inject valid immutable config params
        let valid_owner = H160::random();
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
            "enclave_address": app_state.enclave_address,
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": valid_owner,
            "executor_gas_address": H160::zero(),
            "secret_store_gas_address": H160::zero(),
            "ws_rpc_url": WS_URL,
        }));

        // Inject valid mutable config params
        let executor_gas_wallet_key = SigningKey::random(&mut OsRng);
        let secret_store_gas_wallet_key = SigningKey::random(&mut OsRng);
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(executor_gas_wallet_key.verifying_key())
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
                    "enclave_address": app_state.enclave_address,
                    "enclave_public_key": format!(
                        "0x{}",
                        hex::encode(
                            &(app_state
                                .enclave_signer
                                .verifying_key()
                                .to_encoded_point(false)
                                .as_bytes())[1..]
                        )
                    ),
                    "owner_address": valid_owner,
                    "gas_address": public_key_to_address(secret_store_gas_wallet_key.verifying_key()),
                    "ws_rpc_url": WS_URL,
                }),
            );
        }
        let resp = server.get("/tee-details").await;

        resp.assert_status_ok();
        resp.assert_json(&json!({
            "enclave_address": app_state.enclave_address,
            "enclave_public_key": format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            ),
            "owner_address": valid_owner,
            "executor_gas_address": public_key_to_address(executor_gas_wallet_key.verifying_key()),
            "secret_store_gas_address": public_key_to_address(secret_store_gas_wallet_key.verifying_key()),
            "ws_rpc_url": WS_URL.to_owned() + "ws_api_key",
        }));
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct ExportResponse {
        job_capacity: usize,
        storage_capacity: usize,
        sign_timestamp: usize,
        env: u8,
        owner: H160,
        signature: String,
    }

    #[tokio::test]
    // Test the various response cases for the 'export_signed_registration_message' endpoint
    async fn export_signed_registration_message_test() {
        let metrics = Handle::current().metrics();

        let app_state = generate_app_state(false).await;
        let verifying_key = app_state.enclave_signer.verifying_key().to_owned();

        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Mock secret store register details endpoint
        let mock_state =
            mock_get_endpoint(app_state.secret_store_config_port, "/register-details").await;

        // Export the enclave registration details without injecting tee config params
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_bad_request();
        resp.assert_text("Immutable params not configured yet!\n");

        // Inject valid immutable config params
        let valid_owner = H160::random();
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
        let executor_gas_wallet_key = SigningKey::random(&mut OsRng);
        let secret_store_gas_wallet_key = SigningKey::random(&mut OsRng);
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(executor_gas_wallet_key.verifying_key())
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

        let response: Result<ExportResponse, serde_json::Error> =
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
                response.sign_timestamp,
                response.signature
            ),
            verifying_key
        );
        assert_eq!(*app_state.events_listener_active.lock().unwrap(), true);
        let active_tasks = metrics.num_alive_tasks();

        // Export the enclave registration details again
        let resp = server.get("/signed-registration-message").await;

        resp.assert_status_ok();

        let response: Result<ExportResponse, serde_json::Error> =
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
                response.sign_timestamp,
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

        let code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        // Prepare the logs for JobCreated and JobResponded events accordingly
        let mut jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 20
        }))
        .unwrap()
        .into();

        jobs_created_logs.push(get_job_created_log(
            1.into(),
            1.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        ));

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 600
        }))
        .unwrap()
        .into();

        jobs_created_logs.push(get_job_created_log(
            1.into(),
            2.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        ));

        let jobs_responded_logs = vec![
            get_job_responded_log(1.into(), 0.into()),
            get_job_responded_log(1.into(), 1.into()),
            get_job_responded_log(1.into(), 2.into()),
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 3);

        assert_response(responses[0].clone(), 0.into(), 0, "2,5".into());
        assert_response(responses[1].clone(), 1.into(), 0, "2,2,5".into());
        assert_response(responses[2].clone(), 2.into(), 0, "2,2,2,3,5,5".into());
    }

    #[tokio::test]
    // Test a valid job request with user code contract set in uppercase and verify the response
    async fn valid_job_test_with_uppercase_code_contract() {
        let app_state = generate_app_state(true).await;

        let code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];
        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 0, "2,5".into());
    }

    #[tokio::test]
    // Test a valid job request with invalid input and verify the response
    async fn invalid_input_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];
        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            0.into(),
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
                1.into(),
                0.into(),
                0.into(),
                EXECUTION_ENV_ID,
                "fed8ab36cc27831836f6dcb7291049158b4d8df31c0ffb05a3d36ba6555e29d7",
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_address,
            ),
            // Given transaction hash doesn't exist in the expected rpc network
            get_job_created_log(
                1.into(),
                1.into(),
                0.into(),
                EXECUTION_ENV_ID,
                "37b0b2d9dd58d9130781fc914da456c16ec403010e8d4c27b0ea4657a24c8546",
                code_input_bytes,
                user_deadline,
                app_state.enclave_address,
            ),
        ];

        let jobs_responded_logs = vec![
            get_job_responded_log(1.into(), 0.into()),
            get_job_responded_log(1.into(), 1.into()),
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 2);

        assert_response(responses[0].clone(), 0.into(), 1, "".into());
        assert_response(responses[1].clone(), 1.into(), 1, "".into());
    }

    #[tokio::test]
    // Test '2' error code job request and verify the response
    async fn invalid_code_calldata_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "d23370ce64d1679fb53497b882347e25a026ba0bc54536340243ae7464d5d12d";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Calldata corresponding to the provided transaction hash is invalid
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 2, "".into());
    }

    #[tokio::test]
    // Test '3' error code job request and verify the response
    async fn invalid_code_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "96179f60fd7917c04ad9da6dd64690a1a960f39b50029d07919bf2628f5e7fe5";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Code corresponding to the provided transaction hash has a syntax error
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 3, "".into());
    }

    #[tokio::test]
    // Test '4' error code job request and verify the response
    async fn deadline_timeout_job_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "9c641b535e5586200d0f2fd81f05a39436c0d9dd35530e9fb3ca18352c3ba111";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code didn't return a response in the expected period
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 4, "".into());
    }

    #[tokio::test]
    // Test the execution timeout case where enough job responses are not received and slashing transaction should be sent for the job request
    async fn timeout_job_execution_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "9c641b535e5586200d0f2fd81f05a39436c0d9dd35530e9fb3ca18352c3ba111";
        let user_deadline = 5000;
        let execution_buffer_time = app_state.execution_buffer_time;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Add log entry to relay a job but job response event is not sent and the executor doesn't execute the job request
        let jobs_created_logs = vec![
            get_job_created_log(
                1.into(),
                0.into(),
                0.into(),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes,
                user_deadline,
                H160::random(),
            ),
            Log {
                ..Default::default()
            },
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);
        let job_response = responses[0].clone();
        assert_eq!(job_response.txn_type, JobsTxnType::TIMEOUT);
        assert_eq!(job_response.job_id, 0.into());
        assert!(job_response.job_output.is_none());
    }

    #[tokio::test]
    // Test ExecutorDeregistered event handling
    async fn executor_deregistered_test() {
        let app_state = generate_app_state(false).await;
        app_state.enclave_registered.store(true, Ordering::SeqCst);

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

        // Add log for deregistering the current executor
        let executor_deregistered_logs = vec![Log {
            address: H160::from_str(TEE_MANAGER_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256("ExecutorDeregistered(address)").into(),
                H256::from(app_state.enclave_address),
            ],
            removed: Some(false),
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

        let code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into();

        // Prepare the logs for JobCreated log for different env ID '2'
        let jobs_created_logs = vec![
            get_job_created_log(
                1.into(),
                0.into(),
                0.into(),
                2,
                code_hash,
                code_input_bytes,
                user_deadline,
                app_state.enclave_address,
            ),
            Log {
                ..Default::default()
            },
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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
        let code_hash = "9fa3e2632fdefe0986cac05b839dd4df8d492dbcfc85ec1a5b647e1fd8ed3157";
        let user_deadline = 5000;

        // Case 1: Output size is exceeds the limit
        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "len": MAX_OUTPUT_BYTES_LENGTH + 1
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 5, "".into());
    }

    #[tokio::test]
    //Test Output size is equals to the limit
    async fn output_size_limit_test() {
        let app_state = generate_app_state(false).await;

        // This serverless code return bytes array of given length filled with zeros
        let code_hash = "9fa3e2632fdefe0986cac05b839dd4df8d492dbcfc85ec1a5b647e1fd8ed3157";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({
            "len": MAX_OUTPUT_BYTES_LENGTH
        }))
        .unwrap()
        .into();

        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes,
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }
        assert_eq!(responses.len(), 1);
        let expected_resp: Bytes = Bytes::from_static(&[0u8; MAX_OUTPUT_BYTES_LENGTH]);
        assert_response(responses[0].clone(), 0.into(), 0, expected_resp);
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

        let code_hash = "5db45b92247332b2f4aaa2b6f18f91b0ad50728f9257471c56baa1d45355ac54";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code returning a string containing the secret data
        let jobs_created_logs = vec![
            get_job_created_log(
                1.into(),
                0.into(),
                1.into(),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_address,
            ),
            get_job_created_log(
                1.into(),
                1.into(),
                2.into(),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes,
                user_deadline,
                app_state.enclave_address,
            ),
        ];

        let jobs_responded_logs = vec![
            get_job_responded_log(1.into(), 0.into()),
            get_job_responded_log(1.into(), 1.into()),
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 2);

        assert_response(
            responses[0].clone(),
            0.into(),
            0,
            "Hello World my secret is Secret!\n".into(),
        );
        assert_response(
            responses[1].clone(),
            1.into(),
            0,
            "Hello World my secret is Oyster123!\n".into(),
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

        let code_hash = "b288530f1e50b61094101edb395756fc6a449973ac30eb70762337494ee77bd7";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code returning a string containing the secret data after 10 secs delay
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            1.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(responses[0].clone(), 0.into(), 4, "".into());
    }

    #[tokio::test]
    // Test '6' error code, code execution overloads cgroup memory
    async fn job_execution_out_of_memory_test() {
        let app_state = generate_app_state(false).await;

        // Create a temporary store directory inside the parent
        let temp_dir = Builder::new()
            .prefix("store")
            .rand_bytes(0)
            .tempdir_in("./")
            .expect("Failed to create temporary store directory");

        // Create a secret file with id 1 and length 35000000 (~ 35 MiB)
        let file_path = temp_dir.path().join("1.bin");
        std::fs::write(&file_path, Bytes::from_static(&[0u8; 35000000]))
            .expect("Failed to write to file ./store/1.bin");

        let code_hash = "5db45b92247332b2f4aaa2b6f18f91b0ad50728f9257471c56baa1d45355ac54";
        let user_deadline = 10000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code returning a string containing the secret data
        let jobs_created_logs = vec![
            get_job_created_log(
                1.into(),
                0.into(),
                1.into(),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_address,
            ),
            get_job_created_log(
                1.into(),
                1.into(),
                1.into(),
                EXECUTION_ENV_ID,
                code_hash,
                code_input_bytes.clone(),
                user_deadline,
                app_state.enclave_address,
            ),
        ];

        let jobs_responded_logs = vec![
            get_job_responded_log(1.into(), 0.into()),
            get_job_responded_log(1.into(), 1.into()),
        ];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 2);

        assert_response(responses[0].clone(), 0.into(), 6, "".into());
        assert_response(responses[1].clone(), 1.into(), 6, "".into());
    }

    #[tokio::test]
    // Test code execution that overflows stack size
    async fn job_execution_stack_overflow_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "140531f7fd083d81e3b310c8ae4a4b4ee9fee8e64c7f8cec933765c881448952";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code invokes deep recursion
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            0.into(),
            0,
            "Internal Server Error".into(),
        );
    }

    #[tokio::test]
    // Test code execution that bloats heap size
    async fn job_execution_heap_bloat_test() {
        let app_state = generate_app_state(false).await;

        let code_hash = "09b81077b2596b065c1d7c8fe1a6bd3637919718b99c0198b3ac3532f527f87a";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code invokes excessive heap allocation
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
            0.into(),
            0.into(),
            EXECUTION_ENV_ID,
            code_hash,
            code_input_bytes.clone(),
            user_deadline,
            app_state.enclave_address,
        )];

        let jobs_responded_logs = vec![get_job_responded_log(1.into(), 0.into())];

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

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

        let mut responses: Vec<JobsTxnMetadata> = vec![];

        // Receive and store the responses
        while let Some(job_response) = rx.recv().await {
            responses.push(job_response);
        }

        assert_eq!(responses.len(), 1);

        assert_response(
            responses[0].clone(),
            0.into(),
            0,
            "Internal Server Error".into(),
        );
    }

    fn get_job_created_log(
        block_number: U64,
        job_id: U256,
        secret_id: U256,
        env_id: u8,
        code_hash: &str,
        code_inputs: Bytes,
        user_deadline: u64,
        enclave: H160,
    ) -> Log {
        Log {
            block_number: Some(block_number),
            address: H160::from_str(JOBS_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256("JobCreated(uint256,uint8,address,bytes32,bytes,uint256,address[])")
                    .into(),
                H256::from_uint(&job_id),
                H256::from_uint(&env_id.into()),
                H256::from(H160::random()),
            ],
            data: encode(&[
                Token::Uint(secret_id),
                Token::FixedBytes(hex::decode(code_hash).unwrap()),
                Token::Bytes(code_inputs.into()),
                Token::Uint(user_deadline.into()),
                Token::Array(vec![Token::Address(enclave)]),
            ])
            .into(),
            removed: Some(false),
            ..Default::default()
        }
    }

    fn get_job_responded_log(block_number: U64, job_id: U256) -> Log {
        Log {
            block_number: Some(block_number),
            address: H160::from_str(JOBS_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256("JobResponded(uint256,bytes,uint256,uint8,uint8)").into(),
                H256::from_uint(&job_id),
            ],
            data: encode(&[
                Token::Bytes([].into()),
                Token::Uint(U256::one()),
                Token::Uint((0 as u8).into()),
                Token::Uint((1 as u8).into()),
            ])
            .into(),
            removed: Some(false),
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
        owner: H160,
        job_capacity: usize,
        storage_capacity: usize,
        sign_timestamp: usize,
        sign: String,
    ) -> VerifyingKey {
        // Regenerate the digest for verification
        let domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
            Token::FixedBytes(keccak256("marlin.oyster.TeeManager").to_vec()),
            Token::FixedBytes(keccak256("1").to_vec()),
        ]));
        let register_typehash = keccak256(
            "Register(address owner,uint256 jobCapacity,uint256 storageCapacity,uint8 env,uint256 signTimestamp)",
        );
        let hash_struct = keccak256(encode(&[
            Token::FixedBytes(register_typehash.to_vec()),
            Token::Address(owner),
            Token::Uint(job_capacity.into()),
            Token::Uint(storage_capacity.into()),
            Token::Uint(EXECUTION_ENV_ID.into()),
            Token::Uint(sign_timestamp.into()),
        ]));
        let digest = encode_packed(&[
            Token::String("\x19\x01".to_string()),
            Token::FixedBytes(domain_separator.to_vec()),
            Token::FixedBytes(hash_struct.to_vec()),
        ])
        .unwrap();
        let digest = keccak256(digest);

        let signature =
            Signature::from_slice(hex::decode(&sign[2..130]).unwrap().as_slice()).unwrap();
        let v = RecoveryId::try_from((hex::decode(&sign[130..]).unwrap()[0]) - 27).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(&digest, &signature, v).unwrap();

        return recovered_key;
    }

    fn assert_response(job_response: JobsTxnMetadata, id: U256, error: u8, output: Bytes) {
        assert_eq!(job_response.txn_type, JobsTxnType::OUTPUT);
        assert_eq!(job_response.job_id, id);
        assert!(job_response.job_output.is_some());
        let job_output = job_response.job_output.unwrap();
        println!("{:?}", job_output.output);
        assert_eq!(job_output.error_code, error);
        assert_eq!(job_output.output, output);
    }
}
