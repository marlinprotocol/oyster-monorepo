use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::web::Data;
use alloy::primitives::U256;
use alloy::signers::Signer;
use tokio::time::interval;

use crate::constants::{
    DOMAIN_SEPARATOR, SECRET_EXPIRATION_BUFFER_SECS, SEND_TRANSACTION_BUFFER_SECS,
};
use crate::model::SecretManagerContract::markStoreAliveCall;
use crate::model::{Alive, AppState, SecretMetadata, StoresTransaction};
use crate::utils::check_and_delete_file;

// Periodic job for sending alive acknowledgement transaction and removing expired secret files
pub async fn remove_expired_secrets_and_mark_store_alive(app_state: Data<AppState>) {
    // Start the periodic job with interval 'MARK_ALIVE_TIMEOUT - SEND_TRANSACTION_BUFFER'
    let mut interval = interval(Duration::from_secs(
        app_state.mark_alive_timeout - SEND_TRANSACTION_BUFFER_SECS,
    ));

    loop {
        interval.tick().await; // Wait for the next tick

        // Get the current sign timestamp for signing
        let sign_timestamp = SystemTime::now();
        let sign_timestamp = sign_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let alive_data = Alive {
            signTimestamp: U256::from(sign_timestamp),
        };

        // Sign the digest using enclave key
        let sign = app_state
            .enclave_signer
            .sign_typed_data(&alive_data, &DOMAIN_SEPARATOR)
            .await;
        let Ok(sign) = sign else {
            eprintln!(
                "Failed to sign the alive message using enclave key: {:?}",
                sign.unwrap_err()
            );
            continue;
        };
        let signature = sign.as_bytes();

        // Send the txn response with the mark alive counterpart to the common chain txn sender
        if let Err(err) = app_state
            .tx_sender
            .send(StoresTransaction::MarkStoreAlive(markStoreAliveCall {
                _signTimestamp: U256::from(sign_timestamp),
                _signature: signature.into(),
            }))
            .await
        {
            eprintln!("Failed to send mark alive transaction: {:?}", err);
        };

        // Call the garbage cleaner
        garbage_cleaner(app_state.clone(), false).await;

        // If enclave is deregistered, stop the job because acknowledgments won't be accepted then
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }
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
