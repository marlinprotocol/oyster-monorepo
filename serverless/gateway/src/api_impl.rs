use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;
use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use multi_block_txns::TxnManager;
use serde_json::json;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::{atomic::Ordering, Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::contract_abi::GatewaysContract;
use crate::model::{
    AppState, ContractsClient, GatewayData, GatewayDetailsResponse, ImmutableConfig, MutableConfig,
    RequestChainData, SignedRegistrationBody, SignedRegistrationResponse,
};

pub async fn index() {}

// Endpoint exposed to inject immutable gateway config parameters
pub async fn inject_immutable_config(
    app_state: State<AppState>,
    Json(immutable_config): Json<ImmutableConfig>,
) -> Response {
    let owner_address = Address::from_str(&immutable_config.owner_address_hex);
    let Ok(owner_address) = owner_address else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid owner address provided: {:?}\n",
                owner_address.unwrap_err()
            ),
        )
            .into_response();
    };

    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Immutable params already configured!\n"),
        )
            .into_response();
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = owner_address;
    *immutable_params_injected_guard = true;

    info!("Immutable params configured!");

    return (
        StatusCode::OK,
        String::from("Immutable params configured!\n"),
    )
        .into_response();
}

// Endpoint exposed to inject mutable gateway config parameters
pub async fn inject_mutable_config(
    app_state: State<AppState>,
    Json(mutable_config): Json<MutableConfig>,
) -> Response {
    // Validate the user provided api key
    if !mutable_config
        .ws_api_key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Invalid ws api key provided!\n"),
        )
            .into_response();
    }

    // Validate the user provided gas wallet private key
    let mut bytes32_gas_key = [0u8; 32];
    if let Err(err) = hex::decode_to_slice(&mutable_config.gas_key_hex, &mut bytes32_gas_key) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Failed to hex decode the gas private key into 32 bytes: {:?}\n",
                err
            ),
        )
            .into_response();
    }

    let private_key_signer = mutable_config.gas_key_hex.parse::<PrivateKeySigner>();

    let Ok(_) = private_key_signer else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Failed to parse the gas private key into a private key signer: {:?}\n",
                private_key_signer.unwrap_err()
            ),
        )
            .into_response();
    };

    let contracts_client_guard = app_state.contracts_client.lock().unwrap();

    *app_state.ws_api_key.write().unwrap() = mutable_config.ws_api_key.clone();

    let mut wallet_guard = app_state.wallet.write().unwrap();

    if *wallet_guard != mutable_config.gas_key_hex {
        *wallet_guard = mutable_config.gas_key_hex.clone();
        if contracts_client_guard.is_some() {
            let res = contracts_client_guard
                .as_ref()
                .unwrap()
                .common_chain_txn_manager
                .update_private_signer(mutable_config.gas_key_hex.clone());
            if let Err(e) = res {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Failed to update the private signer for the common chain txn manager: {}\n",
                        e
                    ),
                )
                    .into_response();
            }

            let mut request_chains_data = contracts_client_guard
                .as_ref()
                .unwrap()
                .request_chains_data
                .write()
                .unwrap();
            for request_chain_data in request_chains_data.values_mut() {
                let res = request_chain_data
                    .request_chain_txn_manager
                    .update_private_signer(mutable_config.gas_key_hex.clone());
                if let Err(e) = res {
                    return (StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to update the private signer for the request chain txn manager: {}\n", e)
                    ).into_response();
                }
            }
        }
    }

    app_state
        .mutable_params_injected
        .store(true, Ordering::SeqCst);

    info!("Mutable params configured!");

    return (StatusCode::OK, String::from("Mutable params configured!\n")).into_response();
}

// Endpoint exposed to retrieve the metadata required to register the enclave on the common chain and request chains
pub async fn export_signed_registration_message(
    app_state: State<AppState>,
    Json(signed_registration_body): Json<SignedRegistrationBody>,
) -> Response {
    // if gateway is already registered, return error
    {
        if app_state.registered.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                String::from("Enclave has already been registered.\n"),
            )
                .into_response();
        }
    }

    // check if event listener is active and verify the request_chain_ids
    let chain_ids: HashSet<u64> = signed_registration_body
        .chain_ids
        .clone()
        .into_iter()
        .collect();

    // there should be atleast one request chain id
    if chain_ids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Atleast one request chain id is required!\n"),
        )
            .into_response();
    }

    {
        // verify that the app state request chain ids are same as the signed registration body chain ids
        let request_chain_ids_guard = app_state.request_chain_ids.lock().unwrap();
        if !request_chain_ids_guard.is_empty() && *request_chain_ids_guard != chain_ids {
            return (
                StatusCode::BAD_REQUEST,
                json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": *request_chain_ids_guard,
                })
                .to_string(),
            )
                .into_response();
        }
    }

    // if immutable or mutable params are not configured, return error
    if !*app_state.immutable_params_injected.lock().unwrap() {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Immutable params not configured yet!\n"),
        )
            .into_response();
    }

    // if mutable params are not configured, return error
    if !app_state.mutable_params_injected.load(Ordering::SeqCst) {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Mutable params not configured yet!\n"),
        )
            .into_response();
    }

    // if wallet is not configured, return error
    if app_state.wallet.read().unwrap().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Mutable param wallet not configured yet!\n"),
        )
            .into_response();
    };

    // generate common chain signature
    let enclave_owner = app_state.enclave_owner.lock().unwrap().clone();
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let common_chain_register_typehash =
        keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");

    let chain_ids_tokens: Vec<DynSolValue> = (&chain_ids)
        .into_iter()
        .map(|&x| DynSolValue::Uint(U256::from(x), 256))
        .collect::<Vec<DynSolValue>>();
    let chain_ids_bytes = keccak256(DynSolValue::Array(chain_ids_tokens).abi_encode_packed());

    let hash_struct = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(common_chain_register_typehash, 32),
            DynSolValue::Address(enclave_owner),
            DynSolValue::FixedBytes(chain_ids_bytes, 32),
            DynSolValue::Uint(U256::from(sign_timestamp), 256),
        ])
        .abi_encode(),
    );

    let gateways_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.Gateways"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(gateways_domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer_key
        .sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to sign the registration message using enclave key: {:?}\n",
                sig.unwrap_err()
            ),
        )
            .into_response();
    };
    let common_chain_signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    // create request chain signature and add it to the request chain signatures map
    let request_chain_register_typehash =
        keccak256("Register(address owner,uint256 signTimestamp)");
    let hash_struct = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(request_chain_register_typehash, 32),
            DynSolValue::Address(enclave_owner),
            DynSolValue::Uint(U256::from(sign_timestamp), 256),
        ])
        .abi_encode(),
    );

    let request_chain_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.Relay"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(request_chain_domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer_key
        .sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to sign the registration message using enclave key: {:?}\n",
                sig.unwrap_err()
            ),
        )
            .into_response();
    };

    let request_chain_signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    let common_chain_http_provider =
        ProviderBuilder::new().on_http(Url::parse(&app_state.common_chain_http_url).unwrap());

    let Ok(common_chain_block_number) = common_chain_http_provider.get_block_number().await else {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to fetch the latest block number of the common chain for initiating event listening!\n"
            )
        ).into_response();
    };

    let mut request_chains_data: HashMap<u64, RequestChainData> = HashMap::new();

    let gas_wallet_hex = app_state.wallet.read().unwrap().clone();

    let gateways_contract = Arc::new(GatewaysContract::new(
        app_state.gateways_contract_addr,
        common_chain_http_provider.clone(),
    ));

    // iterate over all chain ids and get their registration signatures
    for &chain_id in &chain_ids {
        // get request chain rpc url
        let request_chain_info = match gateways_contract
            .requestChains(U256::from(chain_id))
            .call()
            .await
        {
            Ok(info) => info,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Failed to fetch the request chain data for chain id {}: {}\n",
                        chain_id, e
                    ),
                )
                    .into_response();
            }
        };

        let request_chain_http_provider = ProviderBuilder::new()
            .on_builtin(&request_chain_info.httpRpcUrl)
            .await;

        let Ok(request_chain_http_provider) = request_chain_http_provider else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to connect to the request chain {} http rpc server {}: {}\n",
                    chain_id,
                    request_chain_info.httpRpcUrl,
                    request_chain_http_provider.unwrap_err()
                ),
            )
                .into_response();
        };

        let block_number = request_chain_http_provider
            .get_block_number()
            .await
            .context(format!(
                "Failed to get the latest block number of the request chain {}",
                chain_id
            ))
            .unwrap();

        drop(request_chain_http_provider);

        let request_chain_txn_manager = TxnManager::new(
            request_chain_info.httpRpcUrl.to_string(),
            chain_id,
            gas_wallet_hex.clone(),
            None,
            None,
            None,
            None,
        );

        let Ok(request_chain_txn_manager) = request_chain_txn_manager else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to create txn manager for request chain {}\n",
                    chain_id
                ),
            )
                .into_response();
        };

        let mut ws_rpc_url = request_chain_info.wsRpcUrl.to_string().clone();
        if !ws_rpc_url.ends_with('/') {
            ws_rpc_url.push('/');
        }
        request_chains_data.insert(
            chain_id,
            RequestChainData {
                chain_id,
                relay_address: request_chain_info.relayAddress.clone(),
                relay_subscriptions_address: request_chain_info.relaySubscriptionsAddress.clone(),
                ws_rpc_url,
                http_rpc_url: request_chain_info.httpRpcUrl.to_string().clone(),
                request_chain_start_block_number: block_number,
                confirmation_blocks: 5,
                last_seen_block: Arc::new(0.into()),
                request_chain_txn_manager,
            },
        );
    }

    let mut request_chain_ids_guard = app_state.request_chain_ids.lock().unwrap();
    if request_chain_ids_guard.is_empty() {
        *request_chain_ids_guard = chain_ids.clone();
    } else {
        if *request_chain_ids_guard != chain_ids {
            return (
                StatusCode::BAD_REQUEST,
                json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": *request_chain_ids_guard,
                })
                .to_string(),
            )
                .into_response();
        }
    }

    let mut registration_events_listener_active_guard = app_state
        .registration_events_listener_active
        .lock()
        .unwrap();

    if *registration_events_listener_active_guard == false {
        let mut contracts_client_guard = app_state.contracts_client.lock().unwrap();

        let gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let gateway_epoch_state_waitlist = Arc::new(RwLock::new(HashMap::new()));

        let subscription_job_instance_heap = Arc::new(RwLock::new(BinaryHeap::new()));
        let subscription_jobs = Arc::new(RwLock::new(HashMap::new()));

        if *gas_wallet_hex != *app_state.wallet.read().unwrap() {
            for request_chain_data in request_chains_data.values_mut() {
                let res = request_chain_data
                    .request_chain_txn_manager
                    .update_private_signer(gas_wallet_hex.clone());
                if let Err(e) = res {
                    return (StatusCode::INTERNAL_SERVER_ERROR, String::from(format!(
                        "Failed to update the private signer for the request chain txn manager: {}\n",
                        e
                    ))).into_response();
                }
            }
        }

        let common_chain_txn_manager = TxnManager::new(
            app_state.common_chain_http_url.clone(),
            app_state.common_chain_id,
            app_state.wallet.read().unwrap().clone(),
            None,
            None,
            None,
            None,
        );

        let Ok(common_chain_txn_manager) = common_chain_txn_manager else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to create txn manager for common chain {}\n",
                    app_state.common_chain_id
                ),
            )
                .into_response();
        };

        let contracts_client = Arc::new(ContractsClient {
            enclave_owner,
            enclave_signer_key: app_state.enclave_signer_key.clone(),
            enclave_address: app_state.enclave_address,
            common_chain_ws_url: app_state.common_chain_ws_url.clone(),
            common_chain_http_url: app_state.common_chain_http_url.clone(),
            common_chain_txn_manager,
            gateways_contract_address: app_state.gateways_contract_addr,
            gateway_jobs_contract_address: app_state.gateway_jobs_contract_addr,
            request_chains_data: Arc::new(RwLock::new(request_chains_data)),
            gateway_epoch_state,
            request_chain_ids: chain_ids.clone(),
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            current_jobs: Arc::new(RwLock::new(HashMap::new())),
            epoch: app_state.epoch,
            time_interval: app_state.time_interval,
            offset_for_epoch: app_state.offset_for_epoch,
            gateway_epoch_state_waitlist,
            common_chain_start_block_number: Arc::new(Mutex::new(common_chain_block_number)),
            subscription_job_instance_heap,
            subscription_jobs,
            ws_api_key: app_state.ws_api_key.clone(),
        });

        *contracts_client_guard = Some(Arc::clone(&contracts_client));

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            contracts_client
                .wait_for_registration(app_state_clone)
                .await;
        });

        *registration_events_listener_active_guard = true;
    }

    let response = SignedRegistrationResponse {
        owner: enclave_owner,
        sign_timestamp: sign_timestamp.try_into().unwrap(),
        chain_ids: signed_registration_body.chain_ids,
        common_chain_signature,
        request_chain_signature,
    };

    (StatusCode::OK, Json(response)).into_response()
}

// Endpoint exposed to retrieve gateway enclave details
pub async fn get_gateway_details(app_state: State<AppState>) -> Response {
    if !*app_state.immutable_params_injected.lock().unwrap() {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Immutable params not configured yet!\n"),
        )
            .into_response();
    }

    if !app_state.mutable_params_injected.load(Ordering::SeqCst) {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Mutable params not configured yet!\n"),
        )
            .into_response();
    }

    let wallet: PrivateKeySigner = app_state
        .wallet
        .read()
        .unwrap()
        .parse::<PrivateKeySigner>()
        .unwrap();

    let response = GatewayDetailsResponse {
        enclave_public_key: "0x".to_string()
            + &hex::encode(
                &app_state
                    .enclave_signer_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()[1..],
            ),
        enclave_address: app_state.enclave_address,
        owner_address: *app_state.enclave_owner.lock().unwrap(),
        gas_address: wallet.address(),
        ws_api_key: app_state.ws_api_key.read().unwrap().clone(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod api_impl_tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::str::FromStr;

    use alloy::signers::k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use axum_test::TestServer;
    use serde_json::json;

    use crate::test_util::{
        generate_app_state, new_app, CHAIN_ID, GAS_WALLET_KEY, GAS_WALLET_PUBLIC_ADDRESS,
        OWNER_ADDRESS, WS_API_KEY,
    };

    // Test the response for the 'index' endpoint
    #[tokio::test]
    async fn index_test() {
        let app_state = generate_app_state().await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        let resp = server.get("/").await;
        resp.assert_status_ok();
    }

    // Test the various response cases for the 'immutable-config' endpoint
    #[tokio::test]
    async fn inject_immutable_config_test() {
        let app_state = generate_app_state().await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Inject invalid hex address string
        let resp = server
            .post("/immutable-config")
            .json(&json!({"owner_address_hex": "0x32255"}))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Invalid owner address provided: OddLength\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), Address::ZERO);

        // Inject invalid hex character address
        let resp = server
            .post("/immutable-config")
            .json(&json!({"owner_address_hex": "0xzfffffffffffffffffffffffffffffffffffffff"}))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Invalid owner address provided: InvalidHexCharacter { c: 'z', index: 0 }\n",
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), Address::ZERO);

        // Inject a valid address
        let resp = server
            .post("/immutable-config")
            .json(&json!({"owner_address_hex": OWNER_ADDRESS}))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            Address::from_str(OWNER_ADDRESS).unwrap()
        );

        // Inject the valid address again
        let resp = server
            .post("/immutable-config")
            .json(&json!({"owner_address_hex": OWNER_ADDRESS}))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Immutable params already configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            Address::from_str(OWNER_ADDRESS).unwrap()
        );
    }

    // Test the various response cases for the 'mutable-config' endpoint
    #[tokio::test]
    async fn inject_mutable_config_test() {
        let app_state = generate_app_state().await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Inject invalid ws api key
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY,
                "ws_api_key": "&&",
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Invalid ws api key provided!\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), String::new());
        assert_eq!(*app_state.ws_api_key.read().unwrap(), String::new());

        // Inject invalid hex private key string
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": "0x32255",
                "ws_api_key": WS_API_KEY,
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text("Failed to hex decode the gas private key into 32 bytes: OddLength\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), String::new());
        assert_eq!(*app_state.ws_api_key.read().unwrap(), String::new());

        // Inject invalid private(signing) key
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ws_api_key": WS_API_KEY,
            }))
            .await;

        resp.assert_status_bad_request();
        resp.assert_text(
            "Failed to hex decode the gas private key into 32 bytes: InvalidStringLength\n",
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), String::new());
        assert_eq!(*app_state.ws_api_key.read().unwrap(), String::new());

        // Inject invalid gas private key hex string (not ecdsa valid key)
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_bad_request();
        resp.assert_text("Failed to parse the gas private key into a private key signer: EcdsaError(signature::Error { source: None })\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), String::new());
        assert_eq!(*app_state.ws_api_key.read().unwrap(), String::new());

        // Inject a valid private key for gas wallet
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY,
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), GAS_WALLET_KEY);
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(app_state.contracts_client.lock().unwrap().is_none());
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.ws_api_key.read().unwrap(), WS_API_KEY);

        // Build contracts client to verify the contracts client public address
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .await;
        resp.assert_status_ok();

        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_ok();
        let gas_wallet_address = app_state
            .contracts_client
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .common_chain_txn_manager
            .clone()
            .get_private_signer()
            .address();
        assert_eq!(
            gas_wallet_address,
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        assert_eq!(
            *app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ws_api_key
                .read()
                .unwrap(),
            WS_API_KEY
        );
        // Inject the same valid private key for gas wallet again
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY,
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), GAS_WALLET_KEY);
        assert_eq!(*app_state.ws_api_key.read().unwrap(), WS_API_KEY);
        let gas_wallet_address = app_state
            .contracts_client
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .common_chain_txn_manager
            .clone()
            .get_private_signer()
            .address();
        assert_eq!(
            gas_wallet_address,
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        assert_eq!(
            *app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ws_api_key
                .read()
                .unwrap(),
            WS_API_KEY
        );

        const GAS_WALLET_KEY_2: &str =
            "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
        const GAS_WALLET_PUBLIC_ADDRESS_2: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

        // Inject another valid private key for gas wallet
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY_2,
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), GAS_WALLET_KEY_2);
        assert_eq!(*app_state.ws_api_key.read().unwrap(), WS_API_KEY);
        let gas_wallet_address = app_state
            .contracts_client
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .common_chain_txn_manager
            .clone()
            .get_private_signer()
            .address();
        assert_eq!(
            gas_wallet_address,
            GAS_WALLET_PUBLIC_ADDRESS_2.parse::<Address>().unwrap()
        );
        assert_eq!(
            *app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ws_api_key
                .read()
                .unwrap(),
            WS_API_KEY
        );

        // Test update api key
        const WS_API_KEY_2: &str = "new_ws_api_key";
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY_2,
                "ws_api_key": WS_API_KEY_2,
            }))
            .await;

        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.read().unwrap(), GAS_WALLET_KEY_2);
        assert_eq!(*app_state.ws_api_key.read().unwrap(), WS_API_KEY_2);
        let gas_wallet_address = app_state
            .contracts_client
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .common_chain_txn_manager
            .clone()
            .get_private_signer()
            .address();
        assert_eq!(
            gas_wallet_address,
            GAS_WALLET_PUBLIC_ADDRESS_2.parse::<Address>().unwrap()
        );
        assert_eq!(
            *app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ws_api_key
                .read()
                .unwrap(),
            WS_API_KEY_2
        );
    }

    fn recover_key(
        chain_ids: Vec<u64>,
        enclave_owner: Address,
        sign_timestamp: usize,
        common_chain_signature: String,
        request_chain_signature: String,
        verifying_key: VerifyingKey,
    ) -> bool {
        let common_chain_register_typehash =
            keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");

        let chain_ids = chain_ids.into_iter().collect::<BTreeSet<u64>>();
        let chain_ids_tokens: Vec<DynSolValue> = (&chain_ids)
            .into_iter()
            .map(|&x| DynSolValue::Uint(U256::from(x), 256))
            .collect::<Vec<DynSolValue>>();
        let chain_ids_bytes = keccak256(DynSolValue::Array(chain_ids_tokens).abi_encode_packed());

        let hash_struct = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(common_chain_register_typehash, 32),
                DynSolValue::Address(enclave_owner),
                DynSolValue::FixedBytes(chain_ids_bytes, 32),
                DynSolValue::Uint(U256::from(sign_timestamp), 256),
            ])
            .abi_encode(),
        );

        let domain_separator = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
                DynSolValue::FixedBytes(keccak256("marlin.oyster.Gateways"), 32),
                DynSolValue::FixedBytes(keccak256("1"), 32),
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

        let signature = Signature::from_slice(
            hex::decode(&common_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&common_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let common_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest.to_vec(), &signature, v).unwrap();

        if common_chain_recovered_key != verifying_key {
            return false;
        }

        // create request chain signature and add it to the request chain signatures map
        let request_chain_register_typehash =
            keccak256("Register(address owner,uint256 signTimestamp)");
        let hash_struct = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(request_chain_register_typehash, 32),
                DynSolValue::Address(enclave_owner),
                DynSolValue::Uint(U256::from(sign_timestamp), 256),
            ])
            .abi_encode(),
        );

        let request_chain_domain_separator = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
                DynSolValue::FixedBytes(keccak256("marlin.oyster.Relay"), 32),
                DynSolValue::FixedBytes(keccak256("1"), 32),
            ])
            .abi_encode(),
        );

        let digest = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::String("\x19\x01".to_string()),
                DynSolValue::FixedBytes(request_chain_domain_separator, 32),
                DynSolValue::FixedBytes(hash_struct, 32),
            ])
            .abi_encode_packed(),
        );

        let signature = Signature::from_slice(
            hex::decode(&request_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&request_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let request_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest.to_vec(), &signature, v).unwrap();

        if request_chain_recovered_key != verifying_key {
            return false;
        }

        true
    }

    #[tokio::test]
    async fn export_signed_registration_message_test() {
        let app_state = generate_app_state().await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Get signature without injecting the operator's address or gas key
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_bad_request();
        resp.assert_text("Immutable params not configured yet!\n");
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid address into the enclave
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature without injecting a gas key
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_bad_request();
        resp.assert_text("Mutable params not configured yet!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid private key
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY,
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with invalid chain id
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": ["invalid u64"]
            }))
            .await;
        resp.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
        assert!(resp
            .as_bytes()
            .starts_with("Failed to deserialize the JSON body into the target type".as_bytes()));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with no chain_ids field in json
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({}))
            .await;
        resp.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
        info!("{}", resp.text());
        assert!(resp.as_bytes().starts_with(
            "Failed to deserialize the JSON body into the target type: missing field `chain_ids`"
                .as_bytes()
        ));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with valid data points
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_ok();

        let response: Result<SignedRegistrationResponse, serde_json::Error> =
            serde_json::from_slice(&resp.as_bytes());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature again with the same chain ids
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_ok();

        let response: Result<SignedRegistrationResponse, serde_json::Error> =
            serde_json::from_slice(&resp.as_bytes());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature with a different chain id
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID + 1]
            }))
            .await;
        resp.assert_status_bad_request();
        assert_eq!(
            resp.as_bytes(),
            json!({
                "message": "Request chain ids mismatch!",
                "chain_ids": [CHAIN_ID],
            })
            .to_string()
            .as_bytes()
        );

        // After on chain registration
        app_state.registered.store(true, Ordering::SeqCst);

        // Get signature after registration
        let resp = server
            .post("/signed-registration-message")
            .json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .await;
        resp.assert_status_bad_request();
        resp.assert_text("Enclave has already been registered.\n");
    }

    #[tokio::test]
    async fn get_gateway_details_test() {
        let app_state = generate_app_state().await;
        let server = TestServer::new(new_app(app_state.clone())).unwrap();

        // Get gateway details without adding wallet and gas key
        let resp = server.get("/gateway-details").await;
        resp.assert_status_bad_request();
        resp.assert_text("Immutable params not configured yet!\n");

        // Inject a valid address into the enclave
        let resp = server
            .post("/immutable-config")
            .json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Immutable params configured!\n");

        // Get gateway details without gas key
        let resp = server.get("/gateway-details").await;
        resp.assert_status_bad_request();
        resp.assert_text("Mutable params not configured yet!\n");

        // Inject a valid private gas key
        let resp = server
            .post("/mutable-config")
            .json(&json!({
                "gas_key_hex": GAS_WALLET_KEY,
                "ws_api_key": WS_API_KEY,
            }))
            .await;
        resp.assert_status_ok();
        resp.assert_text("Mutable params configured!\n");

        // Get gateway details
        let resp = server.get("/gateway-details").await;
        resp.assert_status_ok();

        let response: Result<GatewayDetailsResponse, serde_json::Error> =
            serde_json::from_slice(&resp.as_bytes());
        assert!(response.is_ok());

        let response = response.unwrap();
        let gas_address = app_state
            .wallet
            .read()
            .unwrap()
            .clone()
            .parse::<PrivateKeySigner>()
            .unwrap()
            .address();
        let expected_response = GatewayDetailsResponse {
            enclave_public_key: "0x".to_string()
                + &hex::encode(
                    &app_state
                        .enclave_signer_key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()[1..],
                ),
            enclave_address: app_state.enclave_address,
            owner_address: *app_state.enclave_owner.lock().unwrap(),
            gas_address,
            ws_api_key: WS_API_KEY.to_string(),
        };
        assert_eq!(
            response.enclave_public_key,
            expected_response.enclave_public_key
        );
        assert_eq!(response.enclave_address, expected_response.enclave_address);
        assert_eq!(response.owner_address, expected_response.owner_address);
        assert_eq!(response.gas_address, expected_response.gas_address);
        assert_eq!(response.ws_api_key, expected_response.ws_api_key);
    }
}
