use std::pin::pin;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use actix_web::web::Data;
use alloy::primitives::{keccak256, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use scopeguard::defer;
use tokio::select;
use tokio::time::sleep;
use tokio_stream::{Stream, StreamExt};

use crate::constants::*;
use crate::model::{AppState, SecretCreatedMetadata, SecretManagerContract, SecretMetadata};
use crate::scheduler::{garbage_cleaner, remove_expired_secrets_and_mark_store_alive};
use crate::utils::*;

// Start listening to events emitted by the 'SecretManager' contract if enclave is registered else listen for Store registered event first
pub async fn events_listener(app_state: Data<AppState>, starting_block: u64) {
    defer! {
        *app_state.events_listener_active.lock().unwrap() = false;
    }

    loop {
        // web socket connection
        let web_socket_url = app_state.web_socket_url.read().unwrap().clone();
        let ws_connect = WsConnect::new(web_socket_url);
        let web_socket_client = match ProviderBuilder::new().on_ws(ws_connect).await {
            Ok(client) => client,
            Err(err) => {
                eprintln!(
                    "Failed to connect to the common chain websocket provider: {}",
                    err
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            // Create filter to listen to the 'TeeNodeRegistered' event emitted by the TeeManager contract
            let register_store_filter = Filter::new()
                .address(app_state.tee_manager_contract_addr)
                .event(SECRET_STORE_REGISTERED_EVENT)
                .topic1(B256::from(app_state.enclave_address.into_word()))
                .topic2(B256::from(
                    *app_state.enclave_owner.lock().unwrap().into_word(),
                ))
                .from_block(starting_block);

            // Subscribe to the store registered filter through the rpc web socket client
            let register_subscription = match web_socket_client
                .subscribe_logs(&register_store_filter)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!(
                        "Failed to subscribe to TeeManager ({:?}) contract 'TeeNodeRegistered' event logs: {:?}",
                        app_state.tee_manager_contract_addr,
                        err,
                    );
                    continue;
                }
            };
            let mut register_stream = register_subscription.into_stream();

            while let Some(event) = register_stream.next().await {
                if event.removed {
                    continue;
                }

                app_state.enclave_registered.store(true, Ordering::SeqCst);
                app_state.last_block_seen.store(
                    event.block_number.unwrap_or(starting_block),
                    Ordering::SeqCst,
                );
                app_state.enclave_draining.store(false, Ordering::SeqCst);

                let txn_manager = app_state
                    .http_rpc_txn_manager
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap();
                txn_manager.run().await;

                // Spawn task to submit periodic proofs for secrets stored and remove expired secrets
                let app_state_clone = app_state.clone();
                tokio::spawn(async move {
                    remove_expired_secrets_and_mark_store_alive(app_state_clone).await;
                });

                break;
            }

            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                continue;
            }
        }

        println!("Secret store registered successfully on the common chain!");
        // Create filter to listen to the relevant events emitted by the SecretManager contract
        let secrets_filter = Filter::new()
            .address(app_state.secret_manager_contract_addr)
            .events(vec![
                SECRET_CREATED_EVENT.as_bytes(),
                SECRET_STORE_ACKNOWLEDGEMENT_SUCCESS_EVENT.as_bytes(),
                SECRET_STORE_ACKNOWLEDGEMENT_FAILED_EVENT.as_bytes(),
                SECRET_STORE_REPLACED_EVENT.as_bytes(),
                SECRET_END_TIMESTAMP_UPDATED_EVENT.as_bytes(),
                SECRET_TERMINATED_EVENT.as_bytes(),
                SECRET_REMOVED_EVENT.as_bytes(),
            ])
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the filter through the rpc web socket client
        let secrets_subscription = match web_socket_client.subscribe_logs(&secrets_filter).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to SecretManager ({:?}) contract event logs: {:?}",
                    app_state.secret_manager_contract_addr, err,
                );
                continue;
            }
        };
        let secrets_stream = pin!(secrets_subscription.into_stream());

        // Create filter to listen to relevant events emitted by the TeeManager contract
        let store_filter = Filter::new()
            .address(app_state.tee_manager_contract_addr)
            .events(vec![
                SECRET_STORE_DRAINED_EVENT.as_bytes(),
                SECRET_STORE_REVIVED_EVENT.as_bytes(),
                SECRET_STORE_DEREGISTERED_EVENT.as_bytes(),
            ])
            .topic1(B256::from(app_state.enclave_address.into_word()))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the deregistered filter through the rpc web socket client
        let store_subscription = match web_socket_client.subscribe_logs(&store_filter).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to TeeManager ({:?}) contract event logs: {:?}",
                    app_state.tee_manager_contract_addr, err
                );
                continue;
            }
        };
        let store_stream = pin!(store_subscription.into_stream());

        handle_event_logs(secrets_stream, store_stream, app_state.clone()).await;

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }
    }
}

// Listen to the "SecretStore" & "SecretManager" contract event logs and process them accordingly
async fn handle_event_logs(
    mut secrets_stream: impl Stream<Item = Log> + Unpin,
    mut store_stream: impl Stream<Item = Log> + Unpin,
    app_state: Data<AppState>,
) {
    println!("Started listening to 'SecretManager' and 'TeeManager' events!");

    loop {
        select! {
            Some(event) = store_stream.next() => {
                if event.removed {
                    continue;
                }

                let Some(current_block) = event.block_number else {
                    continue;
                };

                if current_block < app_state.last_block_seen.load(Ordering::SeqCst) {
                    continue;
                }
                app_state.last_block_seen.store(current_block, Ordering::SeqCst);

                // Capture the Enclave deregistered event emitted by the 'TeeManager' contract
                if event.topic0() == Some(&keccak256(SECRET_STORE_DEREGISTERED_EVENT)) {
                    println!("Secret store deregistered from the common chain!");
                    app_state.enclave_registered.store(false, Ordering::SeqCst);

                    println!("Stopped listening to 'SecretManager' events!");
                    return;
                }
                // Capture the Enclave drained event emitted by the 'TeeManager' contract
                else if event.topic0() == Some(&keccak256(SECRET_STORE_DRAINED_EVENT)) {
                    println!("Secret store put in draining mode!");
                    app_state.enclave_draining.store(true, Ordering::SeqCst);
                    // Call the garbage cleaner to clean all secrets stored inside it
                    garbage_cleaner(app_state.clone(), true).await;
                    // Clear all the secrets waiting for acknowledgement and injection
                    app_state.secrets_awaiting_acknowledgement.lock().unwrap().clear();
                    app_state.secrets_created.lock().unwrap().clear();
                }
                // Capture the Enclave revived event emitted by the 'TeeManager' contract
                else if event.topic0() == Some(&keccak256(SECRET_STORE_REVIVED_EVENT)) {
                    println!("Secret store revived from draining mode!");
                    app_state.enclave_draining.store(false, Ordering::SeqCst);
                }
            }
            Some(event) = secrets_stream.next() => {
                if event.removed {
                    continue;
                }

                let Some(current_block) = event.block_number else {
                    continue;
                };

                if current_block < app_state.last_block_seen.load(Ordering::SeqCst) {
                    continue;
                }
                app_state.last_block_seen.store(current_block, Ordering::SeqCst);

                if app_state.enclave_draining.load(Ordering::SeqCst) {
                    continue;
                }

                // Capture the Secret created event emitted by the 'SecretManager' contract
                if event.topic0()
                    == Some(&keccak256(SECRET_CREATED_EVENT))
                {
                    // Extract the 'indexed' parameters of the event
                    let secret_id = U256::from_be_slice(event.topics()[1].as_slice());
                    let secret_owner = b256_to_address(event.topics()[2]);

                    // Decode the event parameters using the ABI information
                    let event_decoded = SecretManagerContract::SecretCreated::decode_log(&event.inner, true);
                    let Ok(event_decoded) = event_decoded else {
                        eprintln!(
                            "Failed to decode 'SecretCreated' event data for secret id {}: {}",
                            secret_id,
                            event_decoded.err().unwrap()
                        );
                        continue;
                    };

                    // Mark the current secret as waiting for acknowledgements
                    app_state
                        .secrets_awaiting_acknowledgement
                        .lock()
                        .unwrap()
                        .insert(secret_id, app_state.num_selected_stores);

                    let app_state_clone = app_state.clone();
                    tokio::spawn(async move {
                        handle_acknowledgement_timeout(secret_id, app_state_clone).await;
                    });

                    // Check if the enclave has been selected for storing the secret
                    let is_node_selected = event_decoded.selectedEnclaves.clone()
                        .into_iter()
                        .any(|addr| addr == app_state.enclave_address);

                    // If selected, store the metadata of the secret created to allow injection via API
                    if is_node_selected {
                        let mut start_timestamp = Instant::now();
                        if let Some(event_block_number) = event.block_number {
                            if let Ok(event_timestamp) =
                                get_block_timestamp(&app_state.http_rpc_url, event_block_number).await {
                                start_timestamp = timestamp_to_instant(event_timestamp).unwrap();
                            }
                        }

                        app_state.secrets_created.lock().unwrap().insert(secret_id, SecretCreatedMetadata {
                            secret_metadata: SecretMetadata {
                                owner: secret_owner,
                                size_limit: event_decoded.sizeLimit,
                                end_timestamp: event_decoded.endTimestamp,
                            },
                            acknowledgement_deadline: start_timestamp
                                + Duration::from_secs(app_state.acknowledgement_timeout),
                        });
                    }
                }
                // Capture the SecretStoreAcknowledgementSuccess event emitted by the SecretManager contract
                else if event.topic0()
                    == Some(&keccak256(SECRET_STORE_ACKNOWLEDGEMENT_SUCCESS_EVENT))
                {
                    // Extract the secret ID from the event
                    let secret_id = U256::from_be_slice(event.topics()[1].as_slice());

                    let mut secrets_awaiting_acknowledgement_guard = app_state
                        .secrets_awaiting_acknowledgement
                        .lock()
                        .unwrap();
                    let Some(secret_ack_count) = secrets_awaiting_acknowledgement_guard.get(&secret_id).cloned() else {
                        continue;
                    };

                    // If the current acknowledgement is the last remaining, remove the secret ID from awaiting acknowledgement
                    if secret_ack_count == 1 {
                        // Mark the secret as acknowledged
                        secrets_awaiting_acknowledgement_guard
                            .remove(&secret_id);
                    }else {
                        // Update the acknowledgement count for the secret ID
                        secrets_awaiting_acknowledgement_guard
                            .insert(secret_id, secret_ack_count-1);
                    }
                }
                // Capture the SecretStoreAcknowledgementFailed event emitted by the SecretManager contract
                else if event.topic0() == Some(&keccak256(SECRET_STORE_ACKNOWLEDGEMENT_FAILED_EVENT))
                    || event.topic0() == Some(&keccak256(SECRET_TERMINATED_EVENT))
                    || event.topic0() == Some(&keccak256(SECRET_REMOVED_EVENT)) {
                    // Extract the secret ID from the event
                    let secret_id = U256::from_be_slice(event.topics()[1].as_slice());
                    // Remove the secret ID from awaiting acknowledgement
                    app_state
                        .secrets_awaiting_acknowledgement
                        .lock()
                        .unwrap()
                        .remove(&secret_id);

                    // Remove the secret ID from awaiting injection/creation
                    app_state
                        .secrets_created
                        .lock()
                        .unwrap()
                        .remove(&secret_id);

                    // Remove the secret if stored already
                    if app_state
                        .secrets_stored
                        .lock()
                        .unwrap()
                        .remove(&secret_id).is_some() {
                        // Remove the secret stored in the filesystem
                        let secret_store_path = app_state.secret_store_path.clone();
                        tokio::spawn(async move {
                            check_and_delete_file(
                                secret_store_path
                                + "/"
                                + &secret_id.to_string()
                                + ".bin",
                            )
                            .await
                        });
                    }
                }
                else if event.topic0() == Some(&keccak256(SECRET_STORE_REPLACED_EVENT)) {
                    // Extract the secret ID from the event
                    let secret_id = U256::from_be_slice(event.topics()[1].as_slice());

                    // Mark the current secret as waiting for acknowledgement
                    {
                        let mut secrets_awaiting_acknowledgement_guard = app_state
                            .secrets_awaiting_acknowledgement
                            .lock()
                            .unwrap();
                        let ack_count  = secrets_awaiting_acknowledgement_guard
                            .get(&secret_id)
                            .cloned()
                            .unwrap_or(0);
                        secrets_awaiting_acknowledgement_guard.insert(secret_id, ack_count+1);
                    }

                    let app_state_clone = app_state.clone();
                    tokio::spawn(async move {
                        handle_acknowledgement_timeout(secret_id, app_state_clone).await;
                    });

                    let new_enclave_address = b256_to_address(event.topics()[3]);
                    if new_enclave_address != app_state.enclave_address {
                        continue;
                    }

                    let secret_metadata =
                        get_secret_metadata(&app_state.secret_manager_contract_instance, secret_id).await;
                    let Ok(secret_metadata) = secret_metadata else {
                        eprintln!(
                            "Failed to extract secret metadata from ID {} for 'SecretStoreReplaced' event: {:?}",
                            secret_id,
                            secret_metadata.unwrap_err());
                        continue;
                    };

                    let mut start_timestamp = Instant::now();
                    if let Some(event_block_number) = event.block_number {
                        if let Ok(event_timestamp) =
                            get_block_timestamp(&app_state.http_rpc_url, event_block_number).await {
                            start_timestamp = timestamp_to_instant(event_timestamp).unwrap();
                        }
                    }

                    app_state.secrets_created.lock().unwrap().insert(secret_id, SecretCreatedMetadata {
                        secret_metadata: secret_metadata,
                        acknowledgement_deadline: start_timestamp
                            + Duration::from_secs(app_state.acknowledgement_timeout),
                    });
                }
                // Capture the SecretEndTimestampUpdated event emitted by the SecretManager contract
                else if event.topic0() == Some(&keccak256(SECRET_END_TIMESTAMP_UPDATED_EVENT)) {
                    // Extract the secret ID from the event
                    let secret_id = U256::from_be_slice(event.topics()[1].as_slice());

                    // Decode the event parameters using the ABI information
                    let event_decoded = SecretManagerContract::SecretEndTimestampUpdated::decode_log(&event.inner, true);
                    let Ok(event_decoded) = event_decoded else {
                        eprintln!(
                            "Failed to decode 'SecretEndTimestampUpdated' event data for secret id {}: {}",
                            secret_id,
                            event_decoded.err().unwrap()
                        );
                        continue;
                    };

                    // Update the end timestamp of the stored secret
                    app_state
                        .secrets_stored
                        .lock()
                        .unwrap()
                        .entry(secret_id)
                        .and_modify(|secret| secret.end_timestamp = event_decoded.endTimestamp);
                }
            }
            else => break,
        }
    }

    println!("Both the 'SecretManager' and 'TeeManager' subscription streams have ended!");
}

// Start task to handle the acknowledgement timeout for a secret created
async fn handle_acknowledgement_timeout(secret_id: U256, app_state: Data<AppState>) {
    // Wait for the acknowledgement timeout to get over for the current secret ID
    sleep(Duration::from_secs(app_state.acknowledgement_timeout + 1)).await;

    // If the secret created has been acknowledged then don't send anything
    if app_state
        .secrets_awaiting_acknowledgement
        .lock()
        .unwrap()
        .remove(&secret_id)
        .is_none()
    {
        return;
    }

    let txn_data = app_state
        .secret_manager_contract_instance
        .acknowledgeStoreFailed(secret_id)
        .calldata()
        .to_owned();

    let http_rpc_txn_manager = app_state
        .http_rpc_txn_manager
        .lock()
        .unwrap()
        .clone()
        .unwrap();

    // Send the txn response with the acknowledgement counterpart to the common chain txn sender
    if let Err(err) = http_rpc_txn_manager
        .call_contract_function(
            app_state.secret_manager_contract_addr,
            txn_data.clone(),
            Instant::now() + Duration::from_secs(ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE_SECS),
        )
        .await
    {
        eprintln!(
            "Failed to send acknowledgement timeout transaction for secret ID {}: {:?}",
            secret_id, err
        );
    };
}
