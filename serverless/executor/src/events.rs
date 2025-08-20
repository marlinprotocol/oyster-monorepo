use std::pin::pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use alloy::hex;
use alloy::primitives::{B256, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use axum::extract::State;
use scopeguard::defer;
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::sleep;
use tokio_stream::{Stream, StreamExt};

use crate::constant::{EXECUTION_ENV_ID, TIMEOUT_TXN_SEND_BUFFER_MS};
use crate::execution::handle_job;
use crate::model::JobsContract::slashOnExecutionTimeoutCall;
use crate::model::{AppState, JobsContract, JobsTransaction, TeeManagerContract};
use crate::transaction::send_transaction;
use crate::utils::get_byte_slice;

// Start listening to Job requests emitted by the Jobs contract if enclave is registered else listen for Executor registered events first
pub async fn events_listener(app_state: State<AppState>, starting_block: u64) {
    defer! {
        *app_state.events_listener_active.lock().unwrap() = false;
    }

    loop {
        // web socket connection
        let ws_rpc_url = app_state.ws_rpc_url.read().unwrap().clone();
        let ws_connect = WsConnect::new(ws_rpc_url);
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
            let register_executor_filter = Filter::new()
                .address(app_state.tee_manager_contract_addr)
                .event(TeeManagerContract::TeeNodeRegistered::SIGNATURE)
                .topic1(B256::from(app_state.enclave_signer.address().into_word()))
                .topic2(B256::from(
                    *app_state.enclave_owner.lock().unwrap().into_word(),
                ))
                .from_block(starting_block);

            // Subscribe to the TeeManager filter through the rpc web socket client
            let register_stream = match web_socket_client
                .subscribe_logs(&register_executor_filter)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!(
                        "Failed to subscribe to TeeManager ({:?}) contract 'TeeNodeRegistered' event logs: {:?}",
                        app_state.tee_manager_contract_addr,
                        err,
                    );
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let mut register_stream = register_stream.into_stream();

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

                break;
            }

            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                continue;
            }
        }

        println!("Executor registered successfully on the common chain!");
        // Create filter to listen to JobCreated events emitted by the Jobs contract for executor's environment
        let jobs_created_filter = Filter::new()
            .address(app_state.jobs_contract_addr)
            .event(JobsContract::JobCreated::SIGNATURE)
            .topic2(B256::from(&get_byte_slice(EXECUTION_ENV_ID)))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the filter through the rpc web socket client
        let jobs_created_stream = match web_socket_client.subscribe_logs(&jobs_created_filter).await
        {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to Jobs ({:?}) contract 'JobCreated' event logs: {:?}",
                    app_state.jobs_contract_addr, err,
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let jobs_created_stream = pin!(jobs_created_stream.into_stream());

        // Create filter to listen to JobResponded events emitted by the Jobs contract
        let jobs_responded_filter = Filter::new()
            .address(app_state.jobs_contract_addr)
            .event(JobsContract::JobResponded::SIGNATURE)
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the filter through the rpc web socket client
        let jobs_responded_stream = match web_socket_client
            .subscribe_logs(&jobs_responded_filter)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to Jobs ({:?}) contract 'JobResponded' event logs: {:?}",
                    app_state.jobs_contract_addr, err,
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let jobs_responded_stream = pin!(jobs_responded_stream.into_stream());

        // Create filter to listen to relevant events emitted by the TeeManager contract
        let executors_filter = Filter::new()
            .address(app_state.tee_manager_contract_addr)
            .events(vec![
                TeeManagerContract::TeeNodeDeregistered::SIGNATURE.as_bytes(),
                TeeManagerContract::TeeNodeDrained::SIGNATURE.as_bytes(),
                TeeManagerContract::TeeNodeRevived::SIGNATURE.as_bytes(),
            ])
            .topic1(B256::from(app_state.enclave_signer.address().into_word()))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the TeeManager filter through the rpc web socket client
        let executors_stream = match web_socket_client.subscribe_logs(&executors_filter).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to TeeManager ({:?}) contract event logs: {:?}",
                    app_state.tee_manager_contract_addr, err
                );
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let executors_stream = pin!(executors_stream.into_stream());

        let (tx, rx) = channel::<JobsTransaction>(100);

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            send_transaction(app_state_clone, rx).await;
        });

        handle_event_logs(
            jobs_created_stream,
            jobs_responded_stream,
            executors_stream,
            app_state.clone(),
            tx,
        )
        .await;

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }
    }
}

// Listen to the "Jobs" & "Executors" contract event logs and process them accordingly
pub async fn handle_event_logs(
    mut jobs_created_stream: impl Stream<Item = Log> + Unpin,
    mut jobs_responded_stream: impl Stream<Item = Log> + Unpin,
    mut executors_stream: impl Stream<Item = Log> + Unpin,
    app_state: State<AppState>,
    tx_sender: Sender<JobsTransaction>,
) {
    println!("Started listening to 'Jobs' and 'TeeManager' events!");

    loop {
        select! {
            Some(event) = executors_stream.next() => {
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

                match event.topic0() {
                    // Capture the Enclave deregistered event emitted by the 'TeeManager' contract
                    Some(&TeeManagerContract::TeeNodeDeregistered::SIGNATURE_HASH) => {
                        println!("Executor deregistered from the common chain!");
                        app_state.enclave_registered.store(false, Ordering::SeqCst);

                        println!("Stopped listening to 'Jobs' events!");
                        return;
                    }
                    // Capture the Enclave drained event emitted by the 'TeeManager' contract
                    Some(&TeeManagerContract::TeeNodeDrained::SIGNATURE_HASH) => {
                        println!("Executor put in draining mode!");
                        app_state.enclave_draining.store(true, Ordering::SeqCst);
                        // Clear the pending jobs map
                        app_state.job_requests_running.lock().unwrap().clear();
                    }
                    // Capture the Enclave revived event emitted by the 'TeeManager' contract
                    Some(&TeeManagerContract::TeeNodeRevived::SIGNATURE_HASH) => {
                        println!("Executor revived from draining mode!");
                        app_state.enclave_draining.store(false, Ordering::SeqCst);
                    }
                    Some(_) => println!("Unrecognized event topic received!"),
                    None => println!("No event topic received!")
                }
            }
            // Capture the Job created event emitted by the jobs contract
            Some(event) = jobs_created_stream.next() => {
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

                // Extract the 'indexed' parameter of the event
                let job_id = U256::from_be_slice(event.topics()[1].as_slice());

                // Extract the 'indexed' env ID and check if it's the same as executor's
                let env_id = U256::from_be_slice(event.topics()[2].as_slice());
                if env_id != U256::from(EXECUTION_ENV_ID) {
                    continue;
                }

                // Decode the event parameters using the ABI information
                let event_decoded = JobsContract::JobCreated::decode_log(&event.inner, true);
                let Ok(event_decoded) = event_decoded else {
                        eprintln!(
                            "Failed to decode 'JobCreated' event data for job id {}: {}",
                            job_id,
                            event_decoded.err().unwrap()
                        );
                        continue;
                    };

                // Mark the current job as under execution
                app_state
                    .job_requests_running
                    .lock()
                    .unwrap()
                    .insert(job_id);

                // Check if the executor has been selected for the job execution
                let is_node_selected = event_decoded.selectedExecutors.clone()
                    .into_iter()
                    .any(|addr| addr == app_state.enclave_signer.address());

                let app_state_clone = app_state.clone();
                let user_deadline = event_decoded.deadline.clone().as_limbs()[0];
                let tx_clone = tx_sender.clone();
                tokio::spawn(async move {
                    handle_timeout(job_id, user_deadline, app_state_clone, tx_clone).await;
                });

                if is_node_selected {
                    let code_hash =
                        String::from("0x".to_owned() + &hex::encode(event_decoded.codehash.as_slice()));
                    let app_state_clone = app_state.clone();
                    let tx_clone = tx_sender.clone();

                    tokio::spawn(async move {
                        handle_job(
                            job_id,
                            event_decoded.secretId,
                            code_hash,
                            event_decoded.codeInputs.clone().into(),
                            event_decoded.deadline.as_limbs()[0],
                            app_state_clone,
                            tx_clone,
                        )
                        .await;
                    });
                }
            }
            // Capture the Job responded event emitted by the Jobs contract
            Some(event) = jobs_responded_stream.next() => {
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

                let job_id = U256::from_be_slice(event.topics()[1].as_slice());

                // Decode the event parameters using the ABI information
                let event_decoded = JobsContract::JobResponded::decode_log(&event.inner, true);
                let Ok(event_decoded) = event_decoded else {
                        eprintln!(
                            "Failed to decode 'JobResponded' event data for job id {}: {}",
                            job_id,
                            event_decoded.err().unwrap()
                        );
                        continue;
                    };

                if event_decoded.outputCount == app_state.num_selected_executors {
                    // Mark the job as completed
                    app_state
                        .job_requests_running
                        .lock()
                        .unwrap()
                        .remove(&job_id);
                }
            }
            else => break,
        }
    }

    println!("Both the 'Jobs' and 'TeeManager' subscription streams have ended!");
}

// Start task to handle the execution timeout scenario for a job request
async fn handle_timeout(
    job_id: U256,
    timeout: u64,
    app_state: State<AppState>,
    tx_sender: Sender<JobsTransaction>,
) {
    sleep(Duration::from_millis(
        timeout + app_state.execution_buffer_time * 1000 + TIMEOUT_TXN_SEND_BUFFER_MS,
    ))
    .await;

    // If the job request had been executed then don't send anything
    if !app_state
        .job_requests_running
        .lock()
        .unwrap()
        .remove(&job_id)
    {
        return;
    }

    // Send the txn response with the execution timeout counterpart to the common chain txn sender
    if let Err(err) = tx_sender
        .send(JobsTransaction::TIMEOUT(slashOnExecutionTimeoutCall {
            _jobId: job_id,
        }))
        .await
    {
        eprintln!(
            "Failed to send execution timeout transaction for job ID {}: {:?}",
            job_id, err
        );
    };
}
