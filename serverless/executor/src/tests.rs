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
    use std::pin::pin;
    use std::str::FromStr;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use actix_web::body::MessageBody;
    use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
    use actix_web::web::{Bytes, Data};
    use actix_web::{http, test, App, Error};
    use ecies::encrypt;
    use ethers::abi::{encode, encode_packed, Token};
    use ethers::types::{Address, BigEndianHash, Log, H160, H256, U256, U64};
    use ethers::utils::{keccak256, public_key_to_address};
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::generic_array::sequence::Lengthen;
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tokio::runtime::Handle;
    use tokio::sync::mpsc::channel;
    use tokio::time::{sleep, Duration};
    use tokio_stream::StreamExt as _;

    use crate::cgroups::Cgroups;
    use crate::event_handler::handle_event_logs;
    use crate::node_handler::*;
    use crate::utils::{
        load_abi_from_file, AppState, JobsTxnMetadata, JobsTxnType, EXECUTION_ENV_ID,
    };

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arb-sepolia.g.alchemy.com/v2/U8uYtmU3xK9j7HEZ74riWfj3C4ode7n1";
    const EXECUTORS_CONTRACT_ADDR: &str = "0xE35E287DBC371561E198bFaCBdbEc9cF78bDe930";
    const JOBS_CONTRACT_ADDR: &str = "0xd3b682f6F58323EC77dEaE730733C6A83a1561Fd";
    const CODE_CONTRACT_ADDR: &str = "0x44fe06d2940b8782a0a9a9ffd09c65852c0156b1";

    // Generate test app state
    async fn generate_app_state() -> Data<AppState> {
        let signer = SigningKey::random(&mut OsRng);
        let signer_verifier_address = public_key_to_address(signer.verifying_key());

        Data::new(AppState {
            job_capacity: 20,
            cgroups: Cgroups::new().unwrap().into(),
            workerd_runtime_path: "./runtime/".to_owned(),
            execution_buffer_time: 10,
            common_chain_id: CHAIN_ID,
            http_rpc_url: HTTP_RPC_URL.to_owned(),
            ws_rpc_url: WS_URL.to_owned(),
            executors_contract_addr: EXECUTORS_CONTRACT_ADDR.parse::<Address>().unwrap(),
            jobs_contract_addr: JOBS_CONTRACT_ADDR.parse::<Address>().unwrap(),
            code_contract_addr: CODE_CONTRACT_ADDR.to_owned(),
            num_selected_executors: 1,
            enclave_address: signer_verifier_address,
            enclave_signer: signer,
            immutable_params_injected: false.into(),
            mutable_params_injected: false.into(),
            enclave_registered: false.into(),
            events_listener_active: false.into(),
            enclave_owner: H160::zero().into(),
            http_rpc_client: None.into(),
            job_requests_running: HashSet::new().into(),
            last_block_seen: 0.into(),
            nonce_to_send: U256::from(0).into(),
            jobs_contract_abi: load_abi_from_file().unwrap(),
        })
    }

    // Return the actix server with the provided app state
    fn new_app(
        app_state: Data<AppState>,
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
            .app_data(app_state)
            .service(index)
            .service(inject_immutable_config)
            .service(inject_mutable_config)
            .service(get_executor_details)
            .service(export_signed_registration_message)
    }

    #[actix_web::test]
    // Test the various response cases for the 'inject_immutable_config' endpoint
    async fn inject_immutable_config_test() {
        let app_state = generate_app_state().await;
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
                "owner_address_hex": "32255G",
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
                "owner_address_hex": "322557",
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Owner address must be 20 bytes long!\n"
        );

        // Inject valid immutable config params
        let valid_owner = H160::random();
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
        let valid_owner_2 = H160::random();
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
    }

    #[actix_web::test]
    // Test the various response cases for the 'inject_mutable_config' endpoint
    async fn inject_mutable_config_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // add owner

        let owner_signer = SigningKey::random(&mut OsRng);
        let owner_address = public_key_to_address(&owner_signer.verifying_key());
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": hex::encode(owner_address),
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);


        // Inject invalid encrypted gas private key hex string (invalid hex character)
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": "fffffffffffffffffzffffffffffffffffffffffffffffgfffffffffffffffff",
                },
                "timestamp": 1734417055,
                "signature": "75fffe0e3bd7363e441728832180ea66922af290fddf00403cc7cee2d30d71c35d19de668f8df0fa3dec5562f823c1befced588f63758ed1d72f3009882428451b"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid gas private key hex string: InvalidHexCharacter { c: 'z', index: 17 }\n"
        );

        // Signature time stamp is too old
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 601;

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                "timestamp": old_ts,
                "signature": "75fffe0e3bd7363e441728832180ea66922af290fddf00403cc7cee2d30d71c35d19de668f8df0fa3dec5562f823c1befced588f63758ed1d72f3009882428451b"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Signature timestamp is too old"
        );

        // Send invalid signature hex string (invalid hex character)
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                "timestamp": current_ts,
                "signature": "gfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid signature hex string: InvalidHexCharacter { c: 'g', index: 0 }\n"
        );

        // Send invalid length of signature bytes, i.e. not equal to 65
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                "timestamp": current_ts,
                "signature": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid signature bytes: InvalidLength(64)\n"
        );

        // test signature verification failure

        // Create signature
        let diff_owner_signer = SigningKey::random(&mut OsRng);
        let gas_wallet_key = SigningKey::random(&mut OsRng);
        let enclave_public_key = app_state.enclave_signer.verifying_key().to_sec1_bytes();
        let encrypted_gas_key = encrypt(&enclave_public_key, &gas_wallet_key.to_bytes().as_slice()).unwrap();
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = diff_owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
        .uri("/mutable-config")
        .set_json(&json!({
            "config": {
                "encrypted_gas_key_hex": hex::encode(encrypted_gas_key.clone()),
            },
            "timestamp": current_ts,
            "signature": signature
        }))
        .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let expected_msg_prefix = "Signature verification failed:";
        assert!(
            resp.into_body().try_into_bytes().unwrap().starts_with(expected_msg_prefix.as_bytes())
        );


        // test decryption of gas wallet private key, size of encrypted gas key is less than 33 (i.e. key size)
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key[..32].to_vec()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
        .uri("/mutable-config")
        .set_json(&json!({
            "config": {
                "encrypted_gas_key_hex": hex::encode(encrypted_gas_key[..32].to_vec()),
            },
            "timestamp": current_ts,
            "signature": signature
        }))
        .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let expected_msg_prefix = "Invalid invalid encrypted gas private key:";
        assert!(
            resp.into_body().try_into_bytes().unwrap().starts_with(expected_msg_prefix.as_bytes())
        );


        // Inject invalid gas private key hex string (less than 32 bytes)
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let encrypted_invalid_gas_key = encrypt(&enclave_public_key, &gas_wallet_key.to_bytes().as_slice()[..6]).unwrap();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_invalid_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_invalid_gas_key),
                },
                "timestamp": current_ts,
                "signature": signature
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Gas private key must be 32 bytes long!\n"
        );

        // Inject invalid gas private key hex string (not ecdsa valid key)
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let invalid_gas_wallet_key = hex::decode(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let encrypted_invalid_gas_key = encrypt(&enclave_public_key, &invalid_gas_wallet_key).unwrap();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_invalid_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_invalid_gas_key),
                },
                "timestamp": current_ts,
                "signature": signature
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid gas private key provided: EcdsaError(signature::Error { source: None })\n"
        );

        // Inject valid mutable config params
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_gas_key.clone()),
                },
                "timestamp": current_ts,
                "signature": signature
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(gas_wallet_key.verifying_key())
        );

        // Inject valid mutable config params again to test mutability
        let gas_wallet_key_2 = SigningKey::random(&mut OsRng);
        let encrypted_gas_key_2 = encrypt(&enclave_public_key, &gas_wallet_key_2.to_bytes().as_slice()).unwrap();
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key_2.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());


        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_gas_key_2.clone()),
                },
                "timestamp": current_ts,
                "signature": signature
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(gas_wallet_key_2.verifying_key())
        );
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct ExecutorDetails {
        enclave_address: H160,
        enclave_public_key: String,
        owner_address: H160,
        gas_address: H160,
    }

    #[actix_web::test]
    // Test the various response cases for the 'get_executor_details' endpoint
    async fn get_executor_details_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // Get the executor details without injecting any config params
        let req = test::TestRequest::get()
            .uri("/executor-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExecutorDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_address);
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, H160::zero());
        assert_eq!(response.gas_address, H160::zero());

        // Inject valid immutable config params
        let owner_signer = SigningKey::random(&mut OsRng);
        let valid_owner = public_key_to_address(&owner_signer.verifying_key());

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

        // Get the executor details without injecting mutable config params
        let req = test::TestRequest::get()
            .uri("/executor-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExecutorDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_address);
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, valid_owner);
        assert_eq!(response.gas_address, H160::zero());

        // Inject valid mutable config params
        let gas_wallet_key = SigningKey::random(&mut OsRng);
        let enclave_public_key = app_state.enclave_signer.verifying_key().to_sec1_bytes();
        let encrypted_gas_key = encrypt(&enclave_public_key, &gas_wallet_key.to_bytes().as_slice()).unwrap();

        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_gas_key.clone()),
                },
                "timestamp": current_ts,
                "signature": signature
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(gas_wallet_key.verifying_key())
        );

        // Get the executor details
        let req = test::TestRequest::get()
            .uri("/executor-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExecutorDetails, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.enclave_address, app_state.enclave_address);
        assert_eq!(
            response.enclave_public_key,
            format!(
                "0x{}",
                hex::encode(
                    &(app_state
                        .enclave_signer
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes())[1..]
                )
            )
        );
        assert_eq!(response.owner_address, valid_owner);
        assert_eq!(
            response.gas_address,
            public_key_to_address(gas_wallet_key.verifying_key())
        );
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct ExportResponse {
        job_capacity: usize,
        sign_timestamp: usize,
        owner: H160,
        signature: String,
    }

    #[actix_web::test]
    // Test the various response cases for the 'export_signed_registration_message' endpoint
    async fn export_signed_registration_message_test() {
        let metrics = Handle::current().metrics();

        let app_state = generate_app_state().await;
        let verifying_key = app_state.enclave_signer.verifying_key().to_owned();

        let app = test::init_service(new_app(app_state.clone())).await;

        // Export the enclave registration details without injecting executor config params
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!\n"
        );

        // Inject valid immutable config params
        let owner_signer = SigningKey::random(&mut OsRng);
        let valid_owner = public_key_to_address(&owner_signer.verifying_key());

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

        // Export the enclave registration details without injecting executor config params
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!\n"
        );

        // Inject valid mutable config params
        let gas_wallet_key = SigningKey::random(&mut OsRng);

        let enclave_public_key = app_state.enclave_signer.verifying_key().to_sec1_bytes();
        let encrypted_gas_key = encrypt(&enclave_public_key, &gas_wallet_key.to_bytes().as_slice()).unwrap();

        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // prepare digest
        let data = encode(&[
            Token::Tuple(vec![
                Token::Bytes(encrypted_gas_key.clone()),
                Token::Uint(current_ts.into())
            ])
        ]);
        let data_hash = keccak256(data);

        let sig = owner_signer.sign_prehash_recoverable(&data_hash);
        let (rs, v) = sig.unwrap();
        let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "config": {
                    "encrypted_gas_key_hex": hex::encode(encrypted_gas_key.clone()),
                },
                "timestamp": current_ts,
                "signature": signature
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
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address(),
            public_key_to_address(gas_wallet_key.verifying_key())
        );

        // Export the enclave registration details
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExportResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.job_capacity, 20);
        assert_eq!(response.owner, valid_owner);
        assert_eq!(response.signature.len(), 132);
        assert_eq!(
            recover_key(
                response.owner,
                response.job_capacity,
                response.sign_timestamp,
                response.signature
            ),
            verifying_key
        );
        assert_eq!(*app_state.events_listener_active.lock().unwrap(), true);
        let active_tasks = metrics.num_alive_tasks();

        // Export the enclave registration details again
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExportResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.job_capacity, 20);
        assert_eq!(response.owner, valid_owner);
        assert_eq!(response.signature.len(), 132);
        assert_eq!(
            recover_key(
                response.owner,
                response.job_capacity,
                response.sign_timestamp,
                response.signature
            ),
            verifying_key
        );
        assert_eq!(active_tasks, metrics.num_alive_tasks());
    }

    #[actix_web::test]
    // Test a valid job request with different inputs and verify the responses
    async fn valid_job_test() {
        let app_state = generate_app_state().await;

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
                app_state,
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

        assert_response(responses[0].clone(), 0.into(), 0, "2,5");
        assert_response(responses[1].clone(), 1.into(), 0, "2,2,5");
        assert_response(responses[2].clone(), 2.into(), 0, "2,2,2,3,5,5");
    }

    #[actix_web::test]
    // Test a valid job request with invalid input and verify the response
    async fn invalid_input_job_test() {
        let app_state = generate_app_state().await;

        let code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
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
                app_state,
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
            "Please provide a valid integer as input in the format{'num':10}",
        );
    }

    #[actix_web::test]
    // Test '1' error code job requests and verify the responses
    async fn invalid_transaction_job_test() {
        let app_state = generate_app_state().await;

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
                app_state,
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

        assert_response(responses[0].clone(), 0.into(), 1, "");
        assert_response(responses[1].clone(), 1.into(), 1, "");
    }

    #[actix_web::test]
    // Test '2' error code job request and verify the response
    async fn invalid_code_calldata_test() {
        let app_state = generate_app_state().await;

        let code_hash = "d23370ce64d1679fb53497b882347e25a026ba0bc54536340243ae7464d5d12d";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Calldata corresponding to the provided transaction hash is invalid
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
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
                app_state,
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

        assert_response(responses[0].clone(), 0.into(), 2, "");
    }

    #[actix_web::test]
    // Test '3' error code job request and verify the response
    async fn invalid_code_job_test() {
        let app_state = generate_app_state().await;

        let code_hash = "96179f60fd7917c04ad9da6dd64690a1a960f39b50029d07919bf2628f5e7fe5";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Code corresponding to the provided transaction hash has a syntax error
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
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
                app_state,
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

        assert_response(responses[0].clone(), 0.into(), 3, "");
    }

    #[actix_web::test]
    // Test '4' error code job request and verify the response
    async fn deadline_timeout_job_test() {
        let app_state = generate_app_state().await;

        let code_hash = "9c641b535e5586200d0f2fd81f05a39436c0d9dd35530e9fb3ca18352c3ba111";
        let user_deadline = 5000;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // User code didn't return a response in the expected period
        let jobs_created_logs = vec![get_job_created_log(
            1.into(),
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
                app_state,
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

        assert_response(responses[0].clone(), 0.into(), 4, "");
    }

    #[actix_web::test]
    // Test the execution timeout case where enough job responses are not received and slashing transaction should be sent for the job request
    async fn timeout_job_execution_test() {
        let app_state = generate_app_state().await;

        let code_hash = "9c641b535e5586200d0f2fd81f05a39436c0d9dd35530e9fb3ca18352c3ba111";
        let user_deadline = 5000;
        let execution_buffer_time = app_state.execution_buffer_time;

        let code_input_bytes: Bytes = serde_json::to_vec(&json!({})).unwrap().into();

        // Add log entry to relay a job but job response event is not sent and the executor doesn't execute the job request
        let jobs_created_logs = vec![
            get_job_created_log(
                1.into(),
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
                app_state,
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

    #[actix_web::test]
    // Test ExecutorDeregistered event handling
    async fn executor_deregistered_test() {
        let app_state = generate_app_state().await;
        app_state.enclave_registered.store(true, Ordering::SeqCst);

        let (tx, mut rx) = channel::<JobsTxnMetadata>(10);

        // Add log for deregistering the current executor
        let executor_deregistered_logs = vec![Log {
            address: H160::from_str(EXECUTORS_CONTRACT_ADDR).unwrap(),
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
                app_state,
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

    #[actix_web::test]
    // Test different env ID job created event
    async fn invalid_env_id_test() {
        let app_state = generate_app_state().await;

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
                app_state,
                tx,
            )
            .await;
        });

        while rx.recv().await.is_some() {
            assert!(false, "Response received for different ENV ID!");
        }
    }

    fn get_job_created_log(
        block_number: U64,
        job_id: U256,
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

    fn recover_key(
        owner: H160,
        job_capacity: usize,
        sign_timestamp: usize,
        sign: String,
    ) -> VerifyingKey {
        // Regenerate the digest for verification
        let domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
            Token::FixedBytes(keccak256("marlin.oyster.Executors").to_vec()),
            Token::FixedBytes(keccak256("1").to_vec()),
        ]));
        let register_typehash = keccak256(
            "Register(address owner,uint256 jobCapacity,uint8 env,uint256 signTimestamp)",
        );
        let hash_struct = keccak256(encode(&[
            Token::FixedBytes(register_typehash.to_vec()),
            Token::Address(owner),
            Token::Uint(job_capacity.into()),
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

    fn assert_response(job_response: JobsTxnMetadata, id: U256, error: u8, output: &str) {
        assert_eq!(job_response.txn_type, JobsTxnType::OUTPUT);
        assert_eq!(job_response.job_id, id);
        assert!(job_response.job_output.is_some());
        let job_output = job_response.job_output.unwrap();

        assert_eq!(job_output.error_code, error);
        assert_eq!(job_output.output, output);
    }
}
