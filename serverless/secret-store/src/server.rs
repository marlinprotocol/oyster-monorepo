use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, Address, U256};
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signature;
use ecies::decrypt;
use multi_block_txns::TxnManager;
use serde_json::json;

use crate::constants::{DOMAIN_SEPARATOR, SECRET_STORAGE_CAPACITY_BYTES};
use crate::events::events_listener;
use crate::model::{AppState, CreateSecret, ImmutableConfig, MutableConfig};
use crate::utils::{create_and_populate_file, get_latest_block_number};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
}

#[post("/immutable-config")]
// Endpoint exposed to inject immutable secret store config parameters
async fn inject_immutable_config(
    Json(immutable_config): Json<ImmutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    // Extract the owner address from the payload
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

    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return HttpResponse::BadRequest().body("Immutable params already configured!\n");
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = Address::from_slice(&owner_address);
    *immutable_params_injected_guard = true;

    HttpResponse::Ok().body("Immutable params configured!\n")
}

#[post("/mutable-config")]
// Endpoint exposed to inject mutable secret store config parameters
async fn inject_mutable_config(
    Json(mutable_config): Json<MutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    // Validate the user provided web socket api key
    if !mutable_config
        .ws_api_key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return HttpResponse::BadRequest().body("API key contains invalid characters!\n");
    }

    // Decode the gas private key from the payload
    let mut bytes32_gas_key = [0u8; 32];
    if let Err(err) = hex::decode_to_slice(&mutable_config.gas_key_hex, &mut bytes32_gas_key) {
        return HttpResponse::BadRequest().body(format!(
            "Failed to hex decode the gas private key into 32 bytes: {:?}\n",
            err
        ));
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain
    let gas_private_key = PrivateKeySigner::from_bytes(&bytes32_gas_key.into());
    let Ok(_) = gas_private_key else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key provided: {:?}\n",
            gas_private_key.unwrap_err()
        ));
    };

    // Initialize HTTP RPC client and nonce for sending the signed transactions
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();

    let mut ws_rpc_url = app_state.web_socket_url.write().unwrap();
    // strip existing api key from the ws url by removing keys after last '/'
    let pos = ws_rpc_url.rfind('/').unwrap();
    ws_rpc_url.truncate(pos + 1);
    ws_rpc_url.push_str(mutable_config.ws_api_key.as_str());
    drop(ws_rpc_url);

    if *mutable_params_injected_guard == false {
        // Connect the rpc http provider with the operator's gas wallet
        let http_rpc_txn_manager = TxnManager::new(
            app_state.http_rpc_url.clone(),
            app_state.common_chain_id,
            mutable_config.gas_key_hex,
            None,
            None,
            None,
            None,
        );

        let Ok(http_rpc_txn_manager) = http_rpc_txn_manager else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to initialize the http rpc txn manager for url {}: {:?}\n",
                app_state.http_rpc_url,
                http_rpc_txn_manager.unwrap_err()
            ));
        };

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
            .update_private_signer(mutable_config.gas_key_hex)
        {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to update the signer for the http rpc txn manager: {:?}\n",
                err
            ));
        }
    }

    HttpResponse::Ok().body("Mutable params configured!\n")
}

#[get("/store-details")]
// Endpoint exposed to retrieve secret store enclave details
async fn get_secret_store_details(app_state: Data<AppState>) -> impl Responder {
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

    HttpResponse::Ok().json(json!({
        "enclave_address": app_state.enclave_address,
        "enclave_public_key": format!("0x{}", hex::encode(&(app_state.enclave_signer.verifying_key().to_encoded_point(false).as_bytes())[1..])),
        "owner_address": *app_state.enclave_owner.lock().unwrap(),
        "gas_address": gas_address,
        "ws_rpc_url": app_state.web_socket_url.read().unwrap().clone(),
    }))
}

#[get("/register-details")]
// Endpoint exposed to retrieve the metadata required to register the secret store on the common chain
async fn export_registration_details(app_state: Data<AppState>) -> impl Responder {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!\n");
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!\n");
    }

    // Get the current block number from the rpc to initiate event listening
    let current_block_number = get_latest_block_number(&app_state.http_rpc_url).await;

    let mut events_listener_active_guard = app_state.events_listener_active.lock().unwrap();
    if *events_listener_active_guard == false {
        let Ok(current_block_number) = current_block_number else {
            return HttpResponse::InternalServerError().body(
                format!("Failed to fetch the latest block number of the common chain for initiating event listening: {:?}\n", 
                current_block_number.unwrap_err())
            );
        };

        *events_listener_active_guard = true;
        drop(events_listener_active_guard);

        tokio::spawn(async move {
            events_listener(app_state, current_block_number).await;
        });
    }

    HttpResponse::Ok().json(json!({
        "storage_capacity": SECRET_STORAGE_CAPACITY_BYTES,
    }))
}

#[post("/inject-secret")]
// Endpoint exposed to verify and store a secret inside the enclave
async fn inject_and_store_secret(
    Json(create_secret): Json<CreateSecret>,
    app_state: Data<AppState>,
) -> impl Responder {
    if !app_state.enclave_registered.load(Ordering::SeqCst) {
        return HttpResponse::BadRequest().body("Secret store enclave not registered yet!\n");
    }

    // Decode the encrypted secret from the payload
    let encrypted_secret_bytes = hex::decode(
        &create_secret
            .encrypted_secret_hex
            .strip_prefix("0x")
            .unwrap_or(&create_secret.encrypted_secret_hex),
    );
    let Ok(encrypted_secret_bytes) = encrypted_secret_bytes else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid encrypted secret hex string: {:?}\n",
            encrypted_secret_bytes.unwrap_err()
        ));
    };

    // Decode the signature from the payload
    let signature_bytes = hex::decode(
        &create_secret
            .signature_hex
            .strip_prefix("0x")
            .unwrap_or(&create_secret.signature_hex),
    );
    let Ok(signature_bytes) = signature_bytes else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid signature hex string: {:?}\n",
            signature_bytes.unwrap_err()
        ));
    };

    // Reconstruct the signature from the bytes data
    let signature = Signature::try_from(signature_bytes.as_slice());
    let Ok(signature) = signature else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid signature : {:?}\n",
            signature.unwrap_err()
        ));
    };

    // Create the digest
    let data_hash = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::Uint(create_secret.secret_id, 256),
            DynSolValue::Bytes(encrypted_secret_bytes.clone()),
        ])
        .abi_encode(),
    );

    // Recover the signer address from the signature and digest
    let recovered_address = signature.recover_address_from_prehash(&data_hash);
    let Ok(recovered_address) = recovered_address else {
        return HttpResponse::BadRequest().body(format!(
            "Failed to recover the signer from the signature: {:?}\n",
            recovered_address.unwrap_err()
        ));
    };

    // Check if the secret ID has been generated from the contract or not
    let Some(secret_created) = app_state
        .secrets_created
        .lock()
        .unwrap()
        .remove(&create_secret.secret_id)
    else {
        return HttpResponse::BadRequest()
            .body("Secret ID not created yet or undergoing injection!\n");
    };

    // Exit if the secret owner is not the same as the secret signer
    if recovered_address != secret_created.secret_metadata.owner {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::BadRequest()
            .body("Signer address not the same as secret owner address!\n");
    }

    // Decrypt the secret data using the enclave signer key
    let decrypted_secret = decrypt(
        &app_state.enclave_signer.to_bytes(),
        &encrypted_secret_bytes,
    );
    let Ok(decrypted_secret) = decrypted_secret else {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::BadRequest().body(format!(
            "Failed to decrypt the encrypted secret using enclave private key: {:?}\n",
            decrypted_secret.unwrap_err()
        ));
    };

    // Exit if the secret data size is greater than the limit received from the SecretManager contract
    if secret_created.secret_metadata.size_limit < U256::from(decrypted_secret.len()) {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::BadRequest()
            .body("Secret data bigger than the expected size limit!\n");
    }

    // Create and store the secret data in the filesystem
    let secret_stored = create_and_populate_file(
        app_state.secret_store_path.to_owned()
            + "/"
            + &create_secret.secret_id.to_string()
            + ".bin",
        &decrypted_secret,
    )
    .await;
    if secret_stored.is_err() {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::InternalServerError().body(format!(
            "Failed to store the secret inside the enclave: {:?}",
            secret_stored.unwrap_err()
        ));
    }

    let sign_timestamp = SystemTime::now();
    app_state
        .secrets_stored
        .lock()
        .unwrap()
        .insert(create_secret.secret_id, secret_created.secret_metadata);
    let sign_timestamp = sign_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Encode and hash the acknowledgement of storing the secret following EIP712 format
    let acknowledge_typehash = keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

    let hash_struct = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(acknowledge_typehash, 32),
            DynSolValue::Uint(create_secret.secret_id, 256),
            DynSolValue::Uint(U256::from(sign_timestamp), 256),
        ])
        .abi_encode(),
    );

    // Create the digest
    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(*DOMAIN_SEPARATOR, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer
        .sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Secret Stored! \nFailed to sign the acknowledgement message using enclave key: {:?}\n",
            sig.unwrap_err()
        ));
    };
    let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

    let txn_data = app_state
        .secret_manager_contract_instance
        .acknowledgeStore(
            create_secret.secret_id,
            U256::from(sign_timestamp),
            signature.clone().into(),
        )
        .calldata()
        .to_owned();

    // Send the txn response with the acknowledgement counterpart to the common chain txn sender
    if let Err(err) = app_state
        .http_rpc_txn_manager
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .call_contract_function(
            app_state.secret_manager_contract_addr,
            txn_data.clone(),
            secret_created.acknowledgement_deadline,
        )
        .await
    {
        eprintln!(
            "Failed to send acknowledgement transaction for secret ID {}: {:?}",
            create_secret.secret_id, err
        );
    };

    HttpResponse::Ok().json(json!({
        "secret_id": create_secret.secret_id,
        "sign_timestamp": sign_timestamp,
        "signature": format!("0x{}", hex::encode(signature)),
    }))
}
