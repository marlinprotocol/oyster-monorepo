use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use ecies::decrypt;
use ethers::abi::{encode, encode_packed, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde_json::json;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::event_handler::events_listener;
use crate::utils::{AppState, ImmutableConfig, SignedMutableConfig, EXECUTION_ENV_ID};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
}

#[post("/immutable-config")]
// Endpoint exposed to inject immutable executor config parameters
async fn inject_immutable_config(
    Json(immutable_config): Json<ImmutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return HttpResponse::BadRequest().body("Immutable params already configured!\n");
    }

    let owner_address = hex::decode(
        &immutable_config
            .owner_address_hex
            .strip_prefix("0x")
            .unwrap_or(&immutable_config.owner_address_hex),
    );
    let Ok(owner_address) = owner_address else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid owner address hex string: {:?}\n",
            owner_address.unwrap_err()
        ));
    };

    if owner_address.len() != 20 {
        return HttpResponse::BadRequest().body("Owner address must be 20 bytes long!\n");
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = H160::from_slice(&owner_address);
    *immutable_params_injected_guard = true;

    HttpResponse::Ok().body("Immutable params configured!\n")
}

#[post("/mutable-config")]
// Endpoint exposed to inject mutable executor config parameters
async fn inject_mutable_config(
    Json(signed_mutable_config): Json<SignedMutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    // decode encrypted gas key
    let encrypted_bytes32_gas_key = hex::decode(
        &signed_mutable_config
            .config
            .encrypted_gas_key_hex
            .strip_prefix("0x")
            .unwrap_or(&signed_mutable_config.config.encrypted_gas_key_hex),
    );
    let Ok(encrypted_bytes32_gas_key) = encrypted_bytes32_gas_key else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key hex string: {:?}\n",
            encrypted_bytes32_gas_key.unwrap_err()
        ));
    };

    // validate that message is signed recently
    let current_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if current_ts > signed_mutable_config.timestamp + 600 {
        return HttpResponse::BadRequest().body("Signature timestamp is too old");
    }

    // decode signature
    let signature_bytes = match hex::decode(
        &signed_mutable_config
            .signature
            .strip_prefix("0x")
            .unwrap_or(&signed_mutable_config.signature),
    ) {
        Ok(data) => data,
        Err(err) => {
            return HttpResponse::BadRequest().body(format!(
                "Invalid signature hex string: {:?}\n",
                err
            ));
        }
    };

    // prepare digest
    let data = encode(&[
        Token::Tuple(vec![
            Token::Bytes(encrypted_bytes32_gas_key.clone()),
            Token::Uint(signed_mutable_config.timestamp.into())
        ])
    ]);
    let data_hash = keccak256(data);

    // Construct the signature from the bytes data
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signautre) => signautre,
        Err(err) => {
            return HttpResponse::BadRequest().body(format!(
                "Invalid signature bytes: {:?}\n",
                err
            ))
        }
    };
    let verify_result = signature.verify(data_hash, *app_state.enclave_owner.lock().unwrap());
    if verify_result.is_err() {
        return HttpResponse::BadRequest().body(format!(
            "Signature verification failed: {} \n",
            verify_result.err().unwrap()
        ));
    };

    // decrypt the private key
    let bytes32_gas_key = match decrypt(
        &app_state.enclave_signer.to_bytes(),
        &encrypted_bytes32_gas_key
    ) {
        Ok(data_bytes) => data_bytes,
        Err(err) => {
            return HttpResponse::BadRequest().body(format!(
                "Invalid invalid encrypted gas private key: {:?}\n",
                err
            ));
        }
    };

    if bytes32_gas_key.len() != 32 {
        return HttpResponse::BadRequest().body("Gas private key must be 32 bytes long!\n");
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain
    let gas_wallet = LocalWallet::from_bytes(&bytes32_gas_key);
    let Ok(gas_wallet) = gas_wallet else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key provided: {:?}\n",
            gas_wallet.unwrap_err()
        ));
    };
    let gas_wallet = gas_wallet.with_chain_id(app_state.common_chain_id);

    // Connect the rpc http provider with the operator's gas wallet
    let http_rpc_client = Provider::<Http>::try_from(&app_state.http_rpc_url);
    let Ok(http_rpc_client) = http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to initialize the http rpc server {}: {:?}\n",
            app_state.http_rpc_url,
            http_rpc_client.unwrap_err()
        ));
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
        return HttpResponse::InternalServerError().body(format!(
            "Failed to fetch current nonce for the gas address: {:?}\n",
            nonce_to_send.unwrap_err()
        ));
    };

    // Initialize HTTP RPC client and nonce for sending the signed transactions while holding lock
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();
    *app_state.nonce_to_send.lock().unwrap() = nonce_to_send;
    *app_state.http_rpc_client.lock().unwrap() = Some(http_rpc_client);
    *mutable_params_injected_guard = true;

    HttpResponse::Ok().body("Mutable params configured!\n")
}

#[get("/executor-details")]
// Endpoint exposed to retrieve executor enclave details
async fn get_executor_details(app_state: Data<AppState>) -> impl Responder {
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

    HttpResponse::Ok().json(json!({
        "enclave_address": app_state.enclave_address,
        "enclave_public_key": format!("0x{}", hex::encode(&(app_state.enclave_signer.verifying_key().to_encoded_point(false).as_bytes())[1..])),
        "owner_address": *app_state.enclave_owner.lock().unwrap(),
        "gas_address": gas_address,
    }))
}

#[get("/signed-registration-message")]
// Endpoint exposed to retrieve the metadata required to register the enclave on the common chain
async fn export_signed_registration_message(app_state: Data<AppState>) -> impl Responder {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!\n");
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!\n");
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
        return HttpResponse::InternalServerError().body(format!(
            "Failed to encode the registration message for signing: {:?}\n",
            digest.unwrap_err()
        ));
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the registration message using enclave key: {:?}\n",
            sig.unwrap_err()
        ));
    };
    let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
    let current_block_number = http_rpc_client.get_block_number().await;

    let mut events_listener_active_guard = app_state.events_listener_active.lock().unwrap();
    if *events_listener_active_guard == false {
        let Ok(current_block_number) = current_block_number else {
            return HttpResponse::InternalServerError().body(format!("Failed to fetch the latest block number of the common chain for initiating event listening: {:?}\n", current_block_number.unwrap_err()));
        };

        *events_listener_active_guard = true;
        drop(events_listener_active_guard);

        tokio::spawn(async move {
            events_listener(app_state, current_block_number).await;
        });
    }

    HttpResponse::Ok().json(json!({
        "job_capacity": job_capacity,
        "sign_timestamp": sign_timestamp,
        "env": EXECUTION_ENV_ID,
        "owner": owner,
        "signature": format!("0x{}", signature),
    }))
}
