use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, Json, response::{IntoResponse, Response}};
use ethers::abi::{encode, encode_packed, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde_json::json;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::event_handler::events_listener;
use crate::utils::{AppState, ExecutorConfig, ImmutableConfig, MutableConfig, EXECUTION_ENV_ID, RegistrationMessage};

pub async fn index() {}

// Endpoint exposed to inject immutable executor config parameters
pub async fn inject_immutable_config(
    app_state: State<AppState>,
    Json(immutable_config): Json<ImmutableConfig>,
) -> Response {
    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return (StatusCode::BAD_REQUEST, String::from("Immutable params already configured!\n")).into_response();
    }

    let owner_address = hex::decode(
        &immutable_config
            .owner_address_hex
            .strip_prefix("0x")
            .unwrap_or(&immutable_config.owner_address_hex),
    );
    let Ok(owner_address) = owner_address else {
        return (
            StatusCode::BAD_REQUEST,
            String::from(format!(
                "Invalid owner address hex string: {:?}\n",
                owner_address.unwrap_err()
            ))
        ).into_response();
    };

    if owner_address.len() != 20 {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Owner address must be 20 bytes long!\n")
        ).into_response();
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = H160::from_slice(&owner_address);
    *immutable_params_injected_guard = true;

    (StatusCode::OK, String::from("Immutable params configured!\n")).into_response()
}

// Endpoint exposed to inject mutable executor config parameters
pub async fn inject_mutable_config(
    app_state: State<AppState>,
    Json(mutable_config): Json<MutableConfig>,
) -> Response {
    let bytes32_gas_key = hex::decode(
        &mutable_config
            .gas_key_hex
            .strip_prefix("0x")
            .unwrap_or(&mutable_config.gas_key_hex),
    );
    let Ok(bytes32_gas_key) = bytes32_gas_key else {
        return (StatusCode::BAD_REQUEST, format!(
            "Invalid gas private key hex string: {:?}\n",
            bytes32_gas_key.unwrap_err()
        )).into_response();
    };

    if bytes32_gas_key.len() != 32 {
        return (StatusCode::BAD_REQUEST, "Gas private key must be 32 bytes long!\n").into_response();
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain
    let gas_wallet = LocalWallet::from_bytes(&bytes32_gas_key);
    let Ok(gas_wallet) = gas_wallet else {
        return (StatusCode::BAD_REQUEST, format!(
            "Invalid gas private key provided: {:?}\n",
            gas_wallet.unwrap_err()
        )).into_response();
    };
    let gas_wallet = gas_wallet.with_chain_id(app_state.common_chain_id);

    // Connect the rpc http provider with the operator's gas wallet
    let http_rpc_client = Provider::<Http>::try_from(&app_state.http_rpc_url);
    let Ok(http_rpc_client) = http_rpc_client else {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!(
            "Failed to initialize the http rpc server {}: {:?}\n",
            app_state.http_rpc_url,
            http_rpc_client.unwrap_err()
        )).into_response();
    };
    let http_rpc_client = http_rpc_client.with_signer(gas_wallet);

    // Fetch current nonce for the injected gas address from the rpc
    let nonce_to_send = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            http_rpc_client
                .get_transaction_count(http_rpc_client.address(), None)
                .await
        },
    )
    .await;
    let Ok(nonce_to_send) = nonce_to_send else {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!(
            "Failed to fetch current nonce for the gas address: {:?}\n",
            nonce_to_send.unwrap_err()
        )).into_response();
    };

    // Initialize HTTP RPC client and nonce for sending the signed transactions while holding lock
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();
    *app_state.nonce_to_send.lock().unwrap() = nonce_to_send;
    *app_state.http_rpc_client.lock().unwrap() = Some(http_rpc_client);
    *mutable_params_injected_guard = true;

    (StatusCode::OK, "Mutable params configured!\n").into_response()
}

// Endpoint exposed to retrieve executor enclave details
pub async fn get_executor_details(app_state: State<AppState>) -> Response {
    let mut gas_address = H160::zero();
    if *app_state.mutable_params_injected.lock().unwrap() == true {
        gas_address = app_state
            .http_rpc_client
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .address();
    }

    let details = ExecutorConfig {
        enclave_address: app_state.enclave_address,
        enclave_public_key: format!("0x{}", hex::encode(&(app_state.enclave_signer.verifying_key().to_encoded_point(false).as_bytes())[1..])),
        owner_address: *app_state.enclave_owner.lock().unwrap(),
        gas_address: gas_address,
    };
    (StatusCode::OK, Json(details)).into_response()
}

// Endpoint exposed to retrieve the metadata required to register the enclave on the common chain
pub async fn export_signed_registration_message(app_state: State<AppState>) -> Response {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return (StatusCode::BAD_REQUEST, "Immutable params not configured yet!\n").into_response();
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return (StatusCode::BAD_REQUEST, "Mutable params not configured yet!\n").into_response();
    }

    let job_capacity = app_state.job_capacity;
    let owner = app_state.enclave_owner.lock().unwrap().clone();
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Encode and hash the job capacity of executor following EIP712 format
    let domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.Executors").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));
    let register_typehash =
        keccak256("Register(address owner,uint256 jobCapacity,uint8 env,uint256 signTimestamp)");

    let hash_struct = keccak256(encode(&[
        Token::FixedBytes(register_typehash.to_vec()),
        Token::Address(owner),
        Token::Uint(job_capacity.into()),
        Token::Uint(EXECUTION_ENV_ID.into()),
        Token::Uint(sign_timestamp.into()),
    ]));

    // Create the digest
    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);
    let Ok(digest) = digest else {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!(
            "Failed to encode the registration message for signing: {:?}\n",
            digest.unwrap_err()
        )).into_response();
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!(
            "Failed to sign the registration message using enclave key: {:?}\n",
            sig.unwrap_err()
        )).into_response();
    };
    let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
    let current_block_number = http_rpc_client.get_block_number().await;

    let mut events_listener_active_guard = app_state.events_listener_active.lock().unwrap();
    if *events_listener_active_guard == false {
        let Ok(current_block_number) = current_block_number else {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!(
                "Failed to fetch the latest block number of the common chain for initiating event listening: {:?}\n",
                current_block_number.unwrap_err()
            )).into_response();
        };

        *events_listener_active_guard = true;
        drop(events_listener_active_guard);

        tokio::spawn(async move {
            events_listener(app_state, current_block_number).await;
        });
    }

    let response_body = RegistrationMessage {
        job_capacity,
        sign_timestamp,
        env: EXECUTION_ENV_ID,
        owner,
        signature: format!("0x{}", signature),
    };

    (StatusCode::OK, Json(response_body)).into_response()
}
