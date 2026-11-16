use std::time::{SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Address, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::eip712_domain;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use multi_block_txns::TxnManager;

use crate::constant::EXECUTION_ENV_ID;
use crate::events::events_listener;
use crate::model::{
    AppState, ImmutableConfig, MutableConfig, Register, RegistrationMessage, TeeConfig,
};
use crate::utils::get_latest_block_number;

pub async fn index() {}

// Endpoint exposed to inject immutable executor config parameters
pub async fn inject_immutable_config(
    app_state: State<AppState>,
    Json(immutable_config): Json<ImmutableConfig>,
) -> Response {
    let owner_address = hex::decode(&immutable_config.owner_address_hex);
    let Ok(owner_address) = owner_address else {
        return (
            StatusCode::BAD_REQUEST,
            String::from(format!(
                "Invalid owner address hex string: {:?}\n",
                owner_address.unwrap_err()
            )),
        )
            .into_response();
    };

    if owner_address.len() != 20 {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Owner address must be 20 bytes long!\n"),
        )
            .into_response();
    }

    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return (
            StatusCode::BAD_REQUEST,
            String::from("Immutable params already configured!\n"),
        )
            .into_response();
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = Address::from_slice(&owner_address);
    *immutable_params_injected_guard = true;

    (
        StatusCode::OK,
        String::from("Immutable params configured!\n"),
    )
        .into_response()
}

// Endpoint exposed to inject mutable executor config parameters
pub async fn inject_mutable_config(
    app_state: State<AppState>,
    Json(mutable_config): Json<MutableConfig>,
) -> Response {
    // Validate the user provided web socket api key
    if !mutable_config
        .ws_api_key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            "API key contains invalid characters!\n",
        )
            .into_response();
    }

    // Decode the gas private key from the payload
    let mut bytes32_gas_key = [0u8; 32];
    if let Err(err) = hex::decode_to_slice(&mutable_config.executor_gas_key, &mut bytes32_gas_key) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Failed to hex decode the gas private key into 32 bytes: {:?}\n",
                err
            ),
        )
            .into_response();
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain
    let gas_private_key = PrivateKeySigner::from_bytes(&bytes32_gas_key.into());
    let Ok(_) = gas_private_key else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid gas private key provided: {:?}\n",
                gas_private_key.unwrap_err()
            ),
        )
            .into_response();
    };

    // Connect the rpc http provider with the operator's gas wallet
    let http_rpc_txn_manager = TxnManager::new(
        app_state.http_rpc_url.clone(),
        app_state.common_chain_id,
        mutable_config.executor_gas_key.clone(),
        None,
        None,
        None,
        None,
    );

    let Ok(http_rpc_txn_manager) = http_rpc_txn_manager else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to initialize the http rpc txn manager for url {}: {:?}\n",
                app_state.http_rpc_url,
                http_rpc_txn_manager.unwrap_err()
            ),
        )
            .into_response();
    };

    // Initialize HTTP RPC client and nonce for sending the signed transactions while holding lock
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();

    let mut ws_rpc_url = app_state.ws_rpc_url.write().unwrap();
    // strip existing api key from the ws url by removing keys after last '/'
    let pos = ws_rpc_url.rfind('/').unwrap();
    ws_rpc_url.truncate(pos + 1);
    ws_rpc_url.push_str(mutable_config.ws_api_key.as_str());

    if *mutable_params_injected_guard == false {
        *app_state.http_rpc_txn_manager.lock().unwrap() = Some(http_rpc_txn_manager);
        *mutable_params_injected_guard = true;
        drop(mutable_params_injected_guard);
    } else {
        if let Err(err) = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .update_private_signer(mutable_config.executor_gas_key)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to update the signer for the http rpc txn manager: {:?}\n",
                    err
                ),
            )
                .into_response();
        }
    }

    (StatusCode::OK, "Mutable params configured!\n").into_response()
}

// Endpoint exposed to retrieve executor enclave details
pub async fn get_tee_details(app_state: State<AppState>) -> Response {
    let mut gas_address = Address::ZERO;
    if *app_state.mutable_params_injected.lock().unwrap() == true {
        gas_address = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .get_private_signer()
            .address();
    }

    let details = TeeConfig {
        enclave_address: app_state.enclave_signer.address(),
        enclave_public_key: format!(
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
        owner_address: *app_state.enclave_owner.lock().unwrap(),
        executor_gas_address: gas_address,
        ws_rpc_url: app_state.ws_rpc_url.read().unwrap().clone(),
    };
    (StatusCode::OK, Json(details)).into_response()
}

// Endpoint exposed to retrieve the metadata required to register the enclave on the common chain
pub async fn export_signed_registration_message(app_state: State<AppState>) -> Response {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return (
            StatusCode::BAD_REQUEST,
            "Immutable params not configured yet!\n",
        )
            .into_response();
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return (
            StatusCode::BAD_REQUEST,
            "Mutable params not configured yet!\n",
        )
            .into_response();
    }

    let job_capacity = app_state.job_capacity;
    let owner = app_state.enclave_owner.lock().unwrap().clone();
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let register_data = Register {
        owner: owner,
        jobCapacity: U256::from(job_capacity),
        env: EXECUTION_ENV_ID,
        signTimestamp: U256::from(sign_timestamp),
    };

    let domain_separator = eip712_domain! {
        name: "marlin.oyster.Executors",
        version: "1",
    };

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer
        .sign_typed_data_sync(&register_data, &domain_separator);
    let Ok(sig) = sig else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to sign the registration message using enclave key: {:?}\n",
                sig.unwrap_err()
            ),
        )
            .into_response();
    };
    let signature = hex::encode(sig.as_bytes());

    let current_block_number = get_latest_block_number(&app_state.http_rpc_url).await;

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
