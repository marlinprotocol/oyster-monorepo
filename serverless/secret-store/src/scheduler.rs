use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use actix_web::web::Data;
use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, U256};
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use tokio::time::interval;

use crate::constants::{
    DOMAIN_SEPARATOR, SECRET_EXPIRATION_BUFFER_SECS, SEND_TRANSACTION_BUFFER_SECS,
};
use crate::model::{AppState, SecretMetadata};
use crate::utils::check_and_delete_file;

// Periodic job for sending alive acknowledgement transaction and removing expired secret files
pub async fn remove_expired_secrets_and_mark_store_alive(app_state: Data<AppState>) {
    // Start the periodic job with interval 'MARK_ALIVE_TIMEOUT - SEND_TRANSACTION_BUFFER'
    let mut interval = interval(Duration::from_secs(
        app_state.mark_alive_timeout - SEND_TRANSACTION_BUFFER_SECS,
    ));

    loop {
        interval.tick().await; // Wait for the next tick

        // If enclave is deregistered, stop the job because acknowledgments won't be accepted then
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }

        // If enclave is drained, skip the alive transaction because acknowledgments won't be accepted then
        if app_state.enclave_draining.load(Ordering::SeqCst) {
            continue;
        }

        // Get the current sign timestamp for signing
        let sign_timestamp = SystemTime::now();
        let sign_timestamp = sign_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Encode and hash the mark store alive message for the secret following EIP712 format
        let alive_typehash = keccak256("Alive(uint256 signTimestamp)");

        let hash_struct = keccak256(
            DynSolValue::Tuple(vec![
                DynSolValue::FixedBytes(alive_typehash, 32),
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
        let sign = app_state
            .enclave_signer
            .sign_prehash_recoverable(&digest.to_vec());
        let Ok((rs, v)) = sign else {
            eprintln!(
                "Failed to sign the alive message using enclave key: {:?}",
                sign.unwrap_err()
            );
            continue;
        };
        let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

        let txn_data = app_state
            .secret_manager_contract_instance
            .markStoreAlive(U256::from(sign_timestamp), signature.into())
            .calldata()
            .to_owned();

        let http_rpc_txn_manager = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        // Send the txn response with the mark alive counterpart
        if let Err(err) = http_rpc_txn_manager
            .call_contract_function(
                app_state.secret_manager_contract_addr,
                txn_data.clone(),
                Instant::now() + Duration::from_secs(SEND_TRANSACTION_BUFFER_SECS),
            )
            .await
        {
            eprintln!("Failed to send store alive transaction: {:?}", err);
        };

        // Call the garbage cleaner
        garbage_cleaner(app_state.clone(), false).await;
    }
}

// Garbage cleaner for removing expired secrets
pub async fn garbage_cleaner(app_state: Data<AppState>, clean_all: bool) {
    // Clone and get the data of secrets stored inside the enclave at the moment
    let secrets_stored: Vec<(U256, SecretMetadata)> = app_state
        .secrets_stored
        .lock()
        .unwrap()
        .iter()
        .map(|(&id, secret)| (id, secret.clone()))
        .collect();

    for (secret_id, secret_metadata) in secrets_stored {
        // If the secret ID has passed its end timestamp plus a buffer, remove it from the storage
        if clean_all
            || SystemTime::now()
                > SystemTime::UNIX_EPOCH
                    + Duration::from_secs(
                        secret_metadata.end_timestamp.to::<u64>() + SECRET_EXPIRATION_BUFFER_SECS,
                    )
        {
            let _ = app_state.secrets_stored.lock().unwrap().remove(&secret_id);

            // Remove the secret stored in the filesystem
            let secret_store_path = app_state.secret_store_path.clone();
            tokio::spawn(async move {
                check_and_delete_file(secret_store_path + "/" + &secret_id.to_string() + ".bin")
                    .await
            });
        }
    }
}
