#[cfg(test)]
pub mod secret_store_test {
    use std::collections::HashMap;
    use std::pin::pin;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Mutex, RwLock};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use actix_web::body::MessageBody;
    use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
    use actix_web::web::Data;
    use actix_web::{http, test, App, Error};
    use alloy::dyn_abi::DynSolValue;
    use alloy::hex;
    use alloy::primitives::{keccak256, Address, LogData, PrimitiveSignature, B256, U256};
    use alloy::rpc::types::Log;
    use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::utils::public_key_to_address;
    use alloy::sol_types::{SolEvent, SolStruct};
    use ecies::encrypt;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tokio::runtime::Handle;
    use tokio::sync::mpsc::{channel, Receiver};
    use tokio::time::{sleep, timeout};
    use tokio_stream::StreamExt;

    use crate::constants::{DOMAIN_SEPARATOR, SECRET_STORAGE_CAPACITY_BYTES};
    use crate::events::handle_event_logs;
    use crate::model::SecretManagerContract::{
        SecretCreated, SecretEndTimestampUpdated, SecretStoreAcknowledgementFailed,
        SecretStoreAcknowledgementSuccess, SecretTerminated,
    };
    use crate::model::TeeManagerContract::{TeeNodeDeregistered, TeeNodeDrained, TeeNodeRevived};
    use crate::model::{Acknowledge, Alive, AppState, StoresTransaction};
    use crate::scheduler::remove_expired_secrets_and_mark_store_alive;
    use crate::server::*;
    use crate::utils::open_and_read_file;

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arb-sepolia.g.alchemy.com/v2/";
    const TEE_MANAGER_CONTRACT_ADDR: &str = "0xFbc9cB063848Db801B382A1Da13E5A213dD378c0";
    const SECRET_MANAGER_CONTRACT_ADDR: &str = "0x6cc663135635c71175a35E4710fC7Ef4e12a085b";

    // Generate test app state
    fn generate_app_state() -> (Data<AppState>, Receiver<StoresTransaction>) {
        let signer = PrivateKeySigner::random();
        let (tx, rx) = channel::<StoresTransaction>(100);

        (
            Data::new(AppState {
                secret_store_path: "./store".to_owned(),
                acknowledgement_timeout: 60,
                mark_alive_timeout: 150,
                common_chain_id: CHAIN_ID,
                http_rpc_url: HTTP_RPC_URL.to_owned(),
                web_socket_url: RwLock::new(WS_URL.to_owned()),
                tee_manager_contract_addr: TEE_MANAGER_CONTRACT_ADDR.parse::<Address>().unwrap(),
                secret_manager_contract_addr: SECRET_MANAGER_CONTRACT_ADDR
                    .parse::<Address>()
                    .unwrap(),
                num_selected_stores: 1,
                enclave_signer: signer,
                immutable_params_injected: Mutex::new(false),
                mutable_params_injected: Mutex::new(false),
                enclave_registered: AtomicBool::new(false),
                events_listener_active: Mutex::new(false),
                enclave_draining: AtomicBool::new(false),
                enclave_owner: Mutex::new(Address::ZERO),
                http_rpc_txn_manager: Mutex::new(None),
                secrets_awaiting_acknowledgement: Mutex::new(HashMap::new()),
                secrets_created: Mutex::new(HashMap::new()),
                secrets_stored: Mutex::new(HashMap::new()),
                last_block_seen: AtomicU64::new(0),
                tx_sender: tx,
            }),
            rx,
        )
    }

    // Return the app with the provided app state
    fn new_app(
        app_data: Data<AppState>,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Response = ServiceResponse<impl MessageBody + std::fmt::Debug>,
            Config = (),
            InitError = (),
            Error = Error,
        >,
    > {
        App::new()
            .service(index)
            .service(inject_immutable_config)
            .service(inject_mutable_config)
            .service(get_secret_store_details)
            .service(export_registration_details)
            .service(inject_and_store_secret)
            .app_data(app_data)
    }

    // TODO: add test attribute
    // Test the various response cases for the 'inject_immutable_config' endpoint
    #[tokio::test]
    async fn inject_immutable_config_test() {
        let (app_state, _) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        // Inject invalid owner address hex string (odd length)
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "32255",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address hex string: OddLength\n"
        );

        // Inject invalid owner address hex string (invalid hex character)
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0x32255G",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address hex string: InvalidHexCharacter { c: 'G', index: 5 }\n"
        );

        // Inject invalid owner address hex string (less than 20 bytes)
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0x322557",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Owner address must be 20 bytes long!\n"
        );

        // Inject valid immutable config params
        let valid_owner = Address::from([0x42; 20]);
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!\n"
        );
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);

        // Inject valid immutable config params again to test immutability
        let valid_owner_2 = Address::from([0x11; 20]);
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": hex::encode(valid_owner_2),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params already configured!\n"
        );
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);
    }

    #[tokio::test]
    // Test the various response cases for the 'inject_mutable_config' endpoint
    async fn inject_mutable_config_test() {
        let (app_state, _) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        // Inject invalid ws_api_key hex string with invalid character
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "0x322557",
                "ws_api_key": "&&&&",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "API key contains invalid characters!\n"
        );

        // Inject invalid gas private key hex string (less than 32 bytes)
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "0x322557",
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: InvalidStringLength\n"
        );

        // Inject invalid gas private key hex string (invalid hex character)
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "fffffffffffffffffzffffffffffffffffffffffffffffgfffffffffffffffff",
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: InvalidHexCharacter { c: 'z', index: 17 }\n"
        );

        // Inject invalid gas private key hex string (not ecdsa valid key)
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid gas private key provided: signature::Error { source: None }\n"
        );

        // Initialize gas wallet key
        let gas_wallet_key = PrivateKeySigner::random();

        // Inject valid mutable config params
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": hex::encode(gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!\n"
        );
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.web_socket_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );

        // Inject valid mutable config params again to test mutability
        let gas_wallet_key = PrivateKeySigner::random();
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": hex::encode(gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key_2",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!\n"
        );
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.web_socket_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key_2"
        );
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct StoreDetails {
        enclave_address: Address,
        enclave_public_key: String,
        owner_address: Address,
        gas_address: Address,
        ws_rpc_url: String,
    }

    #[tokio::test]
    // Test the various response cases for the 'get_secret_store_details' endpoint
    async fn get_secret_store_details_test() {
        let (app_state, _) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        // Get the tee details without injecting any config params
        let req = test::TestRequest::get().uri("/store-details").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<StoreDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_signer.address());
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, Address::ZERO);
        assert_eq!(response.gas_address, Address::ZERO);
        assert_eq!(response.ws_rpc_url, WS_URL);

        // Inject valid immutable config params
        let valid_owner = Address::from([0x42; 20]);
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!\n"
        );
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);

        // Get the details without injecting mutable config params
        let req = test::TestRequest::get().uri("/store-details").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<StoreDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_signer.address());
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, valid_owner);
        assert_eq!(response.gas_address, Address::ZERO);
        assert_eq!(response.ws_rpc_url, WS_URL);

        // Inject valid mutable config params
        let gas_wallet_key = PrivateKeySigner::random();
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": hex::encode(gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!\n"
        );
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.web_socket_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );

        // Get the details
        let req = test::TestRequest::get().uri("/store-details").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<StoreDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_signer.address());
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .credential()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, valid_owner);
        assert_eq!(
            response.gas_address,
            public_key_to_address(gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(response.ws_rpc_url, WS_URL.to_owned() + "ws_api_key");
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct RegisterDetails {
        storage_capacity: usize,
    }

    #[tokio::test]
    // Test the various response cases for the 'export_registration_details' endpoint
    async fn export_registration_details_test() {
        let metrics = Handle::current().metrics();

        let (app_state, _) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        // Export the enclave registration details without injecting tee config params
        let req = test::TestRequest::get()
            .uri("/register-details")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!\n"
        );

        // Inject valid immutable config params
        let valid_owner = Address::from([0x42; 20]);
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": hex::encode(valid_owner),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!\n"
        );
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), valid_owner);

        // Export the enclave registration details without injecting mutable config params
        let req = test::TestRequest::get()
            .uri("/register-details")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!\n"
        );

        // Inject valid mutable config params
        let gas_wallet_key = PrivateKeySigner::random();
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": hex::encode(gas_wallet_key.to_bytes()),
                "ws_api_key": "ws_api_key",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!\n"
        );
        assert_eq!(
            app_state
                .http_rpc_txn_manager
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .get_private_signer()
                .address(),
            public_key_to_address(gas_wallet_key.credential().verifying_key())
        );
        assert_eq!(
            app_state.web_socket_url.read().unwrap().as_str(),
            WS_URL.to_owned() + "ws_api_key"
        );

        // Export the enclave registration details
        let req = test::TestRequest::get()
            .uri("/register-details")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<RegisterDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.storage_capacity, SECRET_STORAGE_CAPACITY_BYTES);
        assert_eq!(*app_state.events_listener_active.lock().unwrap(), true);
        let active_tasks = metrics.num_alive_tasks();

        // Export the enclave registration details again
        let req = test::TestRequest::get()
            .uri("/register-details")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<RegisterDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.storage_capacity, SECRET_STORAGE_CAPACITY_BYTES);
        assert_eq!(*app_state.events_listener_active.lock().unwrap(), true);
        assert_eq!(active_tasks, metrics.num_alive_tasks());
    }

    #[tokio::test]
    // Test the various response cases for the 'inject_and_store_secret' endpoint before creating the secret
    async fn inject_and_store_secret_invalid_test() {
        let (app_state, _) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        // Inject without registering the enclave on chain
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x",
                "signature_hex": "0x",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret store enclave not registered yet!\n"
        );

        app_state.enclave_registered.store(true, Ordering::SeqCst);

        // Inject invalid encrypted secret hex string
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x32255",
                "signature_hex": "0x",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid encrypted secret hex string: OddLength\n"
        );

        // Inject invalid signature hex string
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x322557",
                "signature_hex": "0xG7",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid signature hex string: InvalidHexCharacter { c: 'G', index: 0 }\n"
        );

        // Inject invalid signature
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x322557",
                "signature_hex": "0x322557",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid signature : FromBytes(\"expected exactly 65 bytes\")\n"
        );

        // Inject valid signature but non recoverable
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x322557",
                "signature_hex": "0x5ed7e79e6dc701b35f9e07fa23ce0e8e11f57c191dc42e4f3a238b928548d04d76ac86fae7d164c9d758fa42c9fa886387de8d8a3b4a0fd0d36e05f937e2c95f1c",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to recover the signer from the signature: K256(signature::Error { source: None })\n"
        );

        let wallet = PrivateKeySigner::random();
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(U256::from(1), 256),
                DynSolValue::Bytes(b"0x322557".into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = wallet
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": "0x322557",
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret ID not created yet or undergoing injection!\n"
        );
    }

    #[tokio::test]
    // Test the secret injection acknowledgement timeout case
    async fn secret_acknowledgement_timeout_test() {
        let (app_state, mut rx) = generate_app_state();

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = Address::from([0x11; 20]);
        let size_limit = U256::from(6);
        let duration = 5 * 60;

        // Calculate end timestamp and usdc deposit
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with different selectedEnclave address
        let secret_created_log = vec![create_mock_log(
            app_state.secret_manager_contract_addr,
            1,
            &[
                B256::from(SecretCreated::SIGNATURE_HASH),
                B256::from(secret_id),
                B256::from(owner.into_word()),
            ],
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(size_limit, 256),
                DynSolValue::Uint(end_timestamp, 256),
                DynSolValue::Uint(usdc_deposit, 256),
                DynSolValue::Array(vec![DynSolValue::Address(owner)]),
            ]),
        )];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.acknowledgement_timeout + 15);
        let start_time = Instant::now();

        tokio::spawn(async move {
            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(secret_created_log)),
                pin!(tokio_stream::empty()),
                app_state.clone(),
            )
            .await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(1)).await;

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 1);

        if let StoresTransaction::AcknowledgeStoreFailed(call) = responses[0].clone() {
            assert_eq!(call._secretId, secret_id);
        } else {
            assert!(false, "Acknowledgement timeout transaction not received!");
        }
    }

    #[tokio::test]
    // Test the invalid secret injection cases
    async fn invalid_secret_injection_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;
        app_state.enclave_registered.store(true, Ordering::SeqCst);

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 5 * 60;

        // Calculate end timestamp and usdc deposit
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with different selectedEnclave address
        let secret_created_log = vec![create_mock_log(
            app_state.secret_manager_contract_addr,
            1,
            &[
                B256::from(SecretCreated::SIGNATURE_HASH),
                B256::from(secret_id),
                B256::from(owner.address().into_word()),
            ],
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(size_limit, 256),
                DynSolValue::Uint(end_timestamp, 256),
                DynSolValue::Uint(usdc_deposit, 256),
                DynSolValue::Array(vec![DynSolValue::Address(owner.address())]),
            ]),
        )];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.acknowledgement_timeout + 15);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            // Call the event handler for the contract logs
            handle_event_logs(
                pin!(tokio_stream::iter(secret_created_log)),
                pin!(tokio_stream::empty()),
                app_state_clone,
            )
            .await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(1)).await;

        let encrypted_secret = [0u8; 7];
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature for the created secret
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret ID not created yet or undergoing injection!\n"
        );

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 1);

        if let StoresTransaction::AcknowledgeStoreFailed(call) = responses[0].clone() {
            assert_eq!(call._secretId, secret_id);
        } else {
            assert!(false, "Acknowledgement timeout transaction not received!");
        }

        // Update secret details
        let secret_id = U256::from(2);
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );

        // Create secret log with selectedEnclave address as the enclave address and the corresponding acknowledgement timeout log
        let secret_logs = vec![
            (
                0,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    2,
                    &[
                        B256::from(SecretCreated::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(owner.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(size_limit, 256),
                        DynSolValue::Uint(end_timestamp, 256),
                        DynSolValue::Uint(usdc_deposit, 256),
                        DynSolValue::Array(vec![DynSolValue::Address(
                            app_state.enclave_signer.address(),
                        )]),
                    ]),
                ),
            ),
            (
                app_state.acknowledgement_timeout + 1,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    2,
                    &[
                        B256::from(SecretStoreAcknowledgementFailed::SIGNATURE_HASH),
                        B256::from(secret_id),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
        ];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.acknowledgement_timeout + 15);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(secrets_stream, pin!(tokio_stream::empty()), app_state_clone).await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(1)).await;

        let wallet = PrivateKeySigner::random();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = wallet
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 2,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            format!(
                "Signer address {} not the same as secret owner address!\n",
                wallet.address()
            )
        );

        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature signed by the owner
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 2,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to decrypt the encrypted secret using enclave private key: InvalidMessage\n"
        );

        // Encrypt the secret with enclave's private key
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &encrypted_secret,
        )
        .unwrap();
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature and secret data encrypted by the enclave's private key
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 2,
                "encrypted_secret_hex": hex::encode(encrypted_secret.clone()),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret data bigger than the expected size limit!\n"
        );

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 1);

        if let StoresTransaction::AcknowledgeStoreFailed(call) = responses[0].clone() {
            assert_eq!(call._secretId, secret_id);
        } else {
            assert!(false, "Acknowledgement timeout transaction not received!");
        }

        // Inject secret after the it is terminated because of acknowledgement fail
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 2,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret ID not created yet or undergoing injection!\n"
        );
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct InjectDetails {
        secret_id: U256,
        sign_timestamp: U256,
        signature: String,
    }

    #[tokio::test]
    // Test the valid secret injection case
    async fn valid_secret_injection_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 2 * 60;

        // Calculate end timestamp and usdc deposit
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with selectedEnclave address as the enclave address and the corresponding acknowledgement success log
        let secret_logs = vec![
            (
                0,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretCreated::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(owner.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(size_limit, 256),
                        DynSolValue::Uint(end_timestamp, 256),
                        DynSolValue::Uint(usdc_deposit, 256),
                        DynSolValue::Array(vec![DynSolValue::Address(
                            app_state.enclave_signer.address(),
                        )]),
                    ]),
                ),
            ),
            (
                app_state.acknowledgement_timeout - 2,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretStoreAcknowledgementSuccess::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(app_state.enclave_signer.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
        ];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.mark_alive_timeout + 15);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(secrets_stream, pin!(tokio_stream::empty()), app_state_clone).await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(1)).await;

        // Encrypt the secret with enclave's private key and sign it with owner's wallet
        let secret = [1u8; 6];
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &secret,
        )
        .unwrap();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid recoverable signature with same length as size limit
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<InjectDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.secret_id, secret_id);
        assert_eq!(
            recover_address(Some(secret_id), response.sign_timestamp, response.signature),
            app_state.enclave_signer.address()
        );

        // Verify that the secret has been stored with the same data
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_ok());
        let secret_stored = secret_stored.unwrap();

        assert_eq!(secret_stored, secret.to_vec());

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 3);

        if let StoresTransaction::MarkStoreAlive(call) = responses[0].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        if let StoresTransaction::AcknowledgeStore(call, _) = responses[1].clone() {
            assert_eq!(call._secretId, secret_id);
            assert_eq!(
                recover_address(
                    Some(call._secretId),
                    call._signTimestamp,
                    hex::encode(call._signature)
                ),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(
                false,
                "Secret store acknowledgement transaction not received!"
            );
        }

        if let StoresTransaction::MarkStoreAlive(call) = responses[2].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        // Verify that the secret has been deleted after the garbage collection
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_err());
    }

    #[tokio::test]
    // Test the valid secret injection case with preponed termination
    async fn secret_termination_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 5 * 60;

        // Calculate end timestamp and usdc deposit
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with selectedEnclave address as the enclave address, the corresponding acknowledgement success log and the secret termination log
        let secret_logs = vec![
            (
                0,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretCreated::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(owner.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(size_limit, 256),
                        DynSolValue::Uint(end_timestamp, 256),
                        DynSolValue::Uint(usdc_deposit, 256),
                        DynSolValue::Array(vec![DynSolValue::Address(
                            app_state.enclave_signer.address(),
                        )]),
                    ]),
                ),
            ),
            (
                app_state.acknowledgement_timeout - 2,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretStoreAcknowledgementSuccess::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(app_state.enclave_signer.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
            (
                10,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    2,
                    &[
                        B256::from(SecretTerminated::SIGNATURE_HASH),
                        B256::from(secret_id),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
        ];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.mark_alive_timeout - 2);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(secrets_stream, pin!(tokio_stream::empty()), app_state_clone).await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(2)).await;

        // Encrypt the secret with enclave's private key and sign it with owner's wallet
        let secret = [1u8; 6];
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &secret,
        )
        .unwrap();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid secret data
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<InjectDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.secret_id, secret_id);
        assert_eq!(
            recover_address(Some(secret_id), response.sign_timestamp, response.signature),
            app_state.enclave_signer.address()
        );

        // Verify that the secret has been stored with the same data
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_ok());
        let secret_stored = secret_stored.unwrap();

        assert_eq!(secret_stored, secret.to_vec());

        // Add delay to confirm secret termination
        sleep(Duration::from_secs(app_state.acknowledgement_timeout + 10)).await;

        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_err());

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 3);

        if let StoresTransaction::MarkStoreAlive(call) = responses[0].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        if let StoresTransaction::AcknowledgeStore(call, _) = responses[1].clone() {
            assert_eq!(call._secretId, secret_id);
            assert_eq!(
                recover_address(
                    Some(call._secretId),
                    call._signTimestamp,
                    hex::encode(call._signature)
                ),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(
                false,
                "Secret store acknowledgement transaction not received!"
            );
        }

        if let StoresTransaction::MarkStoreAlive(call) = responses[2].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }
    }

    #[tokio::test]
    // Test the valid secret injection case with end timestamp updated
    async fn secret_end_timestamp_updated_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 2 * 60;

        // Calculate end timestamp, usdc deposit and updated end timestamp
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);
        let end_timestamp_updated = end_timestamp + U256::from(duration);

        // Create secret log with selectedEnclave address as the enclave address, the corresponding acknowledgement success log and the secret end timestamp update log
        let secret_logs = vec![
            (
                0,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretCreated::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(owner.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(size_limit, 256),
                        DynSolValue::Uint(end_timestamp, 256),
                        DynSolValue::Uint(usdc_deposit, 256),
                        DynSolValue::Array(vec![DynSolValue::Address(
                            app_state.enclave_signer.address(),
                        )]),
                    ]),
                ),
            ),
            (
                app_state.acknowledgement_timeout - 2,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretStoreAcknowledgementSuccess::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(app_state.enclave_signer.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
            (
                20,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    2,
                    &[
                        B256::from(SecretEndTimestampUpdated::SIGNATURE_HASH),
                        B256::from(secret_id),
                    ],
                    DynSolValue::Tuple(vec![DynSolValue::Uint(end_timestamp_updated, 256)]),
                ),
            ),
        ];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(2 * app_state.mark_alive_timeout + 2);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(secrets_stream, pin!(tokio_stream::empty()), app_state_clone).await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(2)).await;

        // Encrypt the secret with enclave's private key and sign it with owner's wallet
        let secret = [1u8; 6];
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &secret,
        )
        .unwrap();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid secret data
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<InjectDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.secret_id, secret_id);
        assert_eq!(
            recover_address(Some(secret_id), response.sign_timestamp, response.signature),
            app_state.enclave_signer.address()
        );

        // Verify that the secret has been stored with the same data
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_ok());
        let secret_stored = secret_stored.unwrap();

        assert_eq!(secret_stored, secret.to_vec());

        // add sleep to check secret is still stored because of the end timestamp update
        sleep(Duration::from_secs(duration)).await;

        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_ok());
        let secret_stored = secret_stored.unwrap();

        assert_eq!(secret_stored, secret.to_vec());

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 4);

        if let StoresTransaction::MarkStoreAlive(call) = responses[0].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        if let StoresTransaction::AcknowledgeStore(call, _) = responses[1].clone() {
            assert_eq!(call._secretId, secret_id);
            assert_eq!(
                recover_address(
                    Some(call._secretId),
                    call._signTimestamp,
                    hex::encode(call._signature)
                ),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(
                false,
                "Secret store acknowledgement transaction not received!"
            );
        }

        if let StoresTransaction::MarkStoreAlive(call) = responses[2].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        if let StoresTransaction::MarkStoreAlive(call) = responses[3].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        // check that the secret has been terminated by the garbage collector
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_err());
    }

    #[tokio::test]
    // Test store deregistered event handling
    async fn store_deregistered_test() {
        let (app_state, mut rx) = generate_app_state();

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Add log for deregistering the current secret store
        let store_logs = vec![create_mock_log(
            app_state.tee_manager_contract_addr,
            1,
            &[
                B256::from(TeeNodeDeregistered::SIGNATURE_HASH),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            DynSolValue::Tuple(vec![]),
        )];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.mark_alive_timeout + 10);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let store_stream =
                pin!(tokio_stream::iter(store_logs.into_iter()).chain(tokio_stream::pending()));

            // Call the event handler for the contract logs
            handle_event_logs(pin!(tokio_stream::pending()), store_stream, app_state_clone).await;
        });

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert!(responses.is_empty());
        assert!(
            !app_state.enclave_registered.load(Ordering::SeqCst),
            "Enclave not set to deregistered in the app_state!"
        );
    }

    #[tokio::test]
    // Test store drained event handling
    async fn store_drained_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Add log for draining the current secret store
        let store_logs = vec![create_mock_log(
            app_state.tee_manager_contract_addr,
            1,
            &[
                B256::from(TeeNodeDrained::SIGNATURE_HASH),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            DynSolValue::Tuple(vec![]),
        )];

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 2 * 60;

        // Calculate end timestamp, usdc deposit and updated end timestamp
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with selectedEnclave address as the enclave address
        let secret_logs = vec![(
            5,
            create_mock_log(
                app_state.secret_manager_contract_addr,
                1,
                &[
                    B256::from(SecretCreated::SIGNATURE_HASH),
                    B256::from(secret_id),
                    B256::from(owner.address().into_word()),
                ],
                DynSolValue::Tuple(vec![
                    DynSolValue::Uint(size_limit, 256),
                    DynSolValue::Uint(end_timestamp, 256),
                    DynSolValue::Uint(usdc_deposit, 256),
                    DynSolValue::Array(vec![DynSolValue::Address(
                        app_state.enclave_signer.address(),
                    )]),
                ]),
            ),
        )];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.mark_alive_timeout + 10);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(
                secrets_stream,
                pin!(tokio_stream::iter(store_logs.into_iter())),
                app_state_clone,
            )
            .await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(2)).await;

        // Encrypt the secret with enclave's private key and sign it with owner's wallet
        let secret = [1u8; 6];
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &secret,
        )
        .unwrap();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid secret data
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret ID not created yet or undergoing injection!\n"
        );

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert!(responses.is_empty());
        assert!(
            app_state.enclave_draining.load(Ordering::SeqCst),
            "Secret store not set to draining in the app_state"
        );
    }

    #[tokio::test]
    // Test store revived event handling
    async fn store_revived_test() {
        let (app_state, mut rx) = generate_app_state();
        let app = test::init_service(new_app(app_state.clone())).await;

        app_state.enclave_registered.store(true, Ordering::SeqCst);
        app_state.enclave_draining.store(true, Ordering::SeqCst);
        // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
        });

        // Add log for reviving the current secret store
        let store_logs = vec![create_mock_log(
            app_state.tee_manager_contract_addr,
            1,
            &[
                B256::from(TeeNodeRevived::SIGNATURE_HASH),
                B256::from(app_state.enclave_signer.address().into_word()),
            ],
            DynSolValue::Tuple(vec![]),
        )];

        // Initialize secret details
        let secret_id = U256::from(1);
        let owner = PrivateKeySigner::random();
        let size_limit = U256::from(6);
        let duration = 2 * 60;

        // Calculate end timestamp, usdc deposit and updated end timestamp
        let end_timestamp = U256::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + duration,
        );
        let usdc_deposit = size_limit * U256::from(duration * 10);

        // Create secret log with selectedEnclave address as the enclave address and the corresponding acknowledgement success log
        let secret_logs = vec![
            (
                0,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretCreated::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(owner.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(size_limit, 256),
                        DynSolValue::Uint(end_timestamp, 256),
                        DynSolValue::Uint(usdc_deposit, 256),
                        DynSolValue::Array(vec![DynSolValue::Address(
                            app_state.enclave_signer.address(),
                        )]),
                    ]),
                ),
            ),
            (
                app_state.acknowledgement_timeout - 2,
                create_mock_log(
                    app_state.secret_manager_contract_addr,
                    1,
                    &[
                        B256::from(SecretStoreAcknowledgementSuccess::SIGNATURE_HASH),
                        B256::from(secret_id),
                        B256::from(app_state.enclave_signer.address().into_word()),
                    ],
                    DynSolValue::Tuple(vec![]),
                ),
            ),
        ];

        let mut responses: Vec<StoresTransaction> = vec![];

        // Time for listening to transactions from the receiver channel
        let max_duration = Duration::from_secs(app_state.mark_alive_timeout + 10);
        let start_time = Instant::now();

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            let secrets_stream = pin!(tokio_stream::iter(secret_logs.into_iter()).then(
                |(delay, log)| async move {
                    sleep(Duration::from_secs(delay)).await;
                    log
                }
            ));

            // Call the event handler for the contract logs
            handle_event_logs(
                secrets_stream,
                pin!(tokio_stream::iter(store_logs.into_iter())),
                app_state_clone,
            )
            .await;
        });

        // add sleep delay for the first log to get processed
        sleep(Duration::from_secs(2)).await;

        // Encrypt the secret with enclave's private key and sign it with owner's wallet
        let secret = [1u8; 6];
        let encrypted_secret = encrypt(
            &(app_state
                .enclave_signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes())[1..],
            &secret,
        )
        .unwrap();
        // Create the digest
        let data_hash = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(secret_id, 256),
                DynSolValue::Bytes(encrypted_secret.clone().into()),
            ])
            .abi_encode(),
        );
        let (rs, v) = owner
            .credential()
            .sign_prehash_recoverable(&data_hash.to_vec())
            .unwrap();

        // Inject valid secret data
        let req = test::TestRequest::post()
            .uri("/inject-secret")
            .set_json(&json!({
                "secret_id": 1,
                "encrypted_secret_hex": hex::encode(encrypted_secret),
                "signature_hex": hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<InjectDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.secret_id, secret_id);
        assert_eq!(
            recover_address(Some(secret_id), response.sign_timestamp, response.signature),
            app_state.enclave_signer.address()
        );

        // Verify that the secret has been stored with the same data
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_ok());
        let secret_stored = secret_stored.unwrap();

        assert_eq!(secret_stored, secret.to_vec());

        while start_time.elapsed() < max_duration {
            // Use a small timeout per `recv` to prevent indefinite blocking
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(tx)) => {
                    responses.push(tx);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {}
            }
        }

        assert_eq!(responses.len(), 3);

        if let StoresTransaction::MarkStoreAlive(call) = responses[0].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        if let StoresTransaction::AcknowledgeStore(call, _) = responses[1].clone() {
            assert_eq!(call._secretId, secret_id);
            assert_eq!(
                recover_address(
                    Some(call._secretId),
                    call._signTimestamp,
                    hex::encode(call._signature)
                ),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(
                false,
                "Secret store acknowledgement transaction not received!"
            );
        }

        if let StoresTransaction::MarkStoreAlive(call) = responses[2].clone() {
            assert_eq!(
                recover_address(None, call._signTimestamp, hex::encode(call._signature)),
                app_state.enclave_signer.address()
            );
        } else {
            assert!(false, "Mark store alive transaction not received!");
        }

        // Verify that the secret has been deleted after the garbage collection
        let secret_stored = open_and_read_file(
            app_state.secret_store_path.to_owned() + "/" + &secret_id.to_string() + ".bin",
        )
        .await;

        assert!(secret_stored.is_err());

        assert!(
            !app_state.enclave_draining.load(Ordering::SeqCst),
            "Secret store still draining in the app_state!"
        );
    }

    // Recover signer address from the signature and data
    fn recover_address(secret_id: Option<U256>, sign_timestamp: U256, sign: String) -> Address {
        // Regenerate the digest for verification
        let digest = match secret_id {
            Some(id) => Acknowledge {
                secretId: id,
                signTimestamp: sign_timestamp,
            }
            .eip712_signing_hash(&DOMAIN_SEPARATOR),
            None => Alive {
                signTimestamp: sign_timestamp,
            }
            .eip712_signing_hash(&DOMAIN_SEPARATOR),
        };

        let signature = PrimitiveSignature::from_str(&sign).unwrap();

        return signature.recover_address_from_prehash(&digest).unwrap();
    }

    // Generic function to create mock log for any event struct
    fn create_mock_log(
        contract_address: Address,
        block_num: u64,
        indexed_topics: &[B256],
        event_data: DynSolValue,
    ) -> Log {
        let encoded_data = event_data.abi_encode_sequence().unwrap();

        Log {
            block_number: Some(block_num),
            inner: alloy::primitives::Log {
                address: contract_address,
                data: LogData::new(indexed_topics.to_vec(), encoded_data.into()).unwrap(),
            },
            removed: false,
            ..Default::default()
        }
    }
}
