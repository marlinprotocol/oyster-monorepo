use std::pin::pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::hex;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use axum::extract::State;
use scopeguard::defer;
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::{interval, sleep, timeout};
use tokio_stream::{Stream, StreamExt};

use crate::constant::{
    EXECUTION_ENV_ID, REGISTRATION_CHECK_INTERVAL_SECS, RPC_ERROR_MAX_RETRY_DELAY_SECS,
    RPC_ERROR_RETRY_DELAY_SECS, RPC_REQUEST_TIMEOUT_SECS, TIMEOUT_TXN_SEND_BUFFER_MS,
};
use crate::execution::handle_job;
use crate::model::JobsContract::slashOnExecutionTimeoutCall;
use crate::model::{AppState, JobsContract, JobsTransaction, ExecutorsContract};
use crate::transaction::send_transaction;
use crate::utils::get_byte_slice;

// Start listening to Job requests emitted by the Jobs contract if enclave is registered else wait for the
// registration first, either through the 'ExecutorRegistered' event or by reading the executor on chain
pub async fn events_listener(app_state: State<AppState>) {
    defer! {
        *app_state.events_listener_active.lock().unwrap() = false;
    }

    let mut retry_delay = Duration::ZERO;
    loop {
        // Back off between reconnect attempts, the delay is reset once the subscriptions are set up
        sleep(retry_delay).await;
        retry_delay = next_retry_delay(retry_delay);

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
                continue;
            }
        };

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            // Create filter to listen to the 'ExecutorRegistered' event emitted by the Executors contract
            let register_executor_filter = Filter::new()
                .address(app_state.executors_contract_addr)
                .event(ExecutorsContract::ExecutorRegistered::SIGNATURE)
                .topic1(B256::from(app_state.enclave_signer.address().into_word()))
                .topic2(B256::from(
                    *app_state.enclave_owner.lock().unwrap().into_word(),
                ));

            // Subscribe to the Executors filter through the rpc web socket client
            let register_stream = match web_socket_client
                .subscribe_logs(&register_executor_filter)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!(
                        "Failed to subscribe to Executors ({:?}) contract 'ExecutorRegistered' event logs: {:?}",
                        app_state.executors_contract_addr,
                        err,
                    );
                    continue;
                }
            };
            let mut register_stream = register_stream.into_stream();
            retry_delay = Duration::from_secs(RPC_ERROR_RETRY_DELAY_SECS);

            // The subscription only delivers new events, so also read the registration from the Executors
            // contract: right away (the enclave may already be registered, e.g. after a restart of the
            // executor) and then periodically (the subscription can miss an event while it reconnects)
            let mut registration_check =
                interval(Duration::from_secs(REGISTRATION_CHECK_INTERVAL_SECS));
            loop {
                select! {
                    event = register_stream.next() => {
                        let Some(event) = event else {
                            break;
                        };
                        if event.removed {
                            continue;
                        }

                        let block = event
                            .block_number
                            .unwrap_or(app_state.last_block_seen.load(Ordering::SeqCst));
                        if mark_registered(&app_state, false, block).await {
                            break;
                        }
                    }
                    _ = registration_check.tick() => {
                        match read_registration(&web_socket_client, &app_state).await {
                            Ok((OnChainRegistration::Registered { draining }, block)) => {
                                println!(
                                    "Executor found registered on the common chain (draining: {})",
                                    draining
                                );
                                if mark_registered(&app_state, draining, block).await {
                                    break;
                                }
                            }
                            Ok((OnChainRegistration::NotRegistered, _)) => {}
                            Ok((OnChainRegistration::OwnerMismatch(owner), _)) => {
                                eprintln!(
                                    "Executor is registered on the common chain with owner {:?}, which is not the injected owner {:?}",
                                    owner,
                                    *app_state.enclave_owner.lock().unwrap()
                                );
                            }
                            Err(err) => {
                                eprintln!("Failed to read the executor registration from the Executors contract: {:?}", err);
                            }
                        }
                    }
                }
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
                continue;
            }
        };
        let jobs_responded_stream = pin!(jobs_responded_stream.into_stream());

        // Create filter to listen to relevant events emitted by the Executors contract
        let executors_filter = Filter::new()
            .address(app_state.executors_contract_addr)
            .events(vec![
                ExecutorsContract::ExecutorDeregistered::SIGNATURE.as_bytes(),
                ExecutorsContract::ExecutorDrained::SIGNATURE.as_bytes(),
                ExecutorsContract::ExecutorRevived::SIGNATURE.as_bytes(),
            ])
            .topic1(B256::from(app_state.enclave_signer.address().into_word()))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the Executors filter through the rpc web socket client
        let executors_stream = match web_socket_client.subscribe_logs(&executors_filter).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to Executors ({:?}) contract event logs: {:?}",
                    app_state.executors_contract_addr, err
                );
                continue;
            }
        };
        let executors_stream = pin!(executors_stream.into_stream());

        retry_delay = Duration::from_secs(RPC_ERROR_RETRY_DELAY_SECS);

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

// Delay before the next reconnect attempt: starts at RPC_ERROR_RETRY_DELAY_SECS and doubles up to
// RPC_ERROR_MAX_RETRY_DELAY_SECS
fn next_retry_delay(current: Duration) -> Duration {
    current
        .saturating_mul(2)
        .max(Duration::from_secs(RPC_ERROR_RETRY_DELAY_SECS))
        .min(Duration::from_secs(RPC_ERROR_MAX_RETRY_DELAY_SECS))
}

// Registration state of the enclave as stored in the Executors contract
#[derive(Debug, PartialEq)]
pub(crate) enum OnChainRegistration {
    NotRegistered,
    Registered { draining: bool },
    OwnerMismatch(Address),
}

// Decide the registration state from the 'executors' entry of the enclave, an entry with a zero owner
// means the enclave is not registered (the contract deletes the entry on deregistration)
pub(crate) fn registration_status(
    onchain_owner: Address,
    onchain_draining: bool,
    expected_owner: Address,
) -> OnChainRegistration {
    if onchain_owner == Address::ZERO {
        OnChainRegistration::NotRegistered
    } else if onchain_owner != expected_owner {
        OnChainRegistration::OwnerMismatch(onchain_owner)
    } else {
        OnChainRegistration::Registered {
            draining: onchain_draining,
        }
    }
}

// Read the registration of the enclave from the Executors contract at the latest block, returns the state and
// the block it was read at
async fn read_registration(
    provider: &impl Provider,
    app_state: &State<AppState>,
) -> Result<(OnChainRegistration, u64)> {
    let request_timeout = Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS);
    let block = timeout(request_timeout, provider.get_block_number())
        .await
        .context("Timed out fetching the latest block number")?
        .context("Failed to fetch the latest block number")?;

    let executors_contract = ExecutorsContract::new(app_state.executors_contract_addr, provider);
    let executor = timeout(
        request_timeout,
        executors_contract
            .executors(app_state.enclave_signer.address())
            .block(BlockId::number(block))
            .call(),
    )
    .await
    .context("Timed out reading the executor from the Executors contract")?
    .context("Failed to read the executor from the Executors contract")?;

    Ok((
        registration_status(
            executor.owner,
            executor.draining,
            *app_state.enclave_owner.lock().unwrap(),
        ),
        block,
    ))
}

// Mark the enclave as registered and start the transaction manager, returns false if that is not possible yet
async fn mark_registered(app_state: &State<AppState>, draining: bool, block: u64) -> bool {
    let Some(txn_manager) = app_state.http_rpc_txn_manager.lock().unwrap().clone() else {
        eprintln!("Executor registered but the gas key is not configured yet!");
        return false;
    };

    app_state.enclave_draining.store(draining, Ordering::SeqCst);
    app_state.last_block_seen.store(block, Ordering::SeqCst);
    app_state.enclave_registered.store(true, Ordering::SeqCst);

    txn_manager.run().await;
    true
}

// Listen to the "Jobs" & "Executors" contract event logs and process them accordingly
pub async fn handle_event_logs(
    mut jobs_created_stream: impl Stream<Item = Log> + Unpin,
    mut jobs_responded_stream: impl Stream<Item = Log> + Unpin,
    mut executors_stream: impl Stream<Item = Log> + Unpin,
    app_state: State<AppState>,
    tx_sender: Sender<JobsTransaction>,
) {
    println!("Started listening to 'Jobs' and 'Executors' events!");

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
                    // Capture the Enclave deregistered event emitted by the 'Executors' contract
                    Some(&ExecutorsContract::ExecutorDeregistered::SIGNATURE_HASH) => {
                        println!("Executor deregistered from the common chain!");
                        app_state.enclave_registered.store(false, Ordering::SeqCst);

                        println!("Stopped listening to 'Jobs' events!");
                        return;
                    }
                    // Capture the Enclave drained event emitted by the 'Executors' contract
                    Some(&ExecutorsContract::ExecutorDrained::SIGNATURE_HASH) => {
                        println!("Executor put in draining mode!");
                        app_state.enclave_draining.store(true, Ordering::SeqCst);
                        // Clear the pending jobs map
                        app_state.job_requests_running.lock().unwrap().clear();
                    }
                    // Capture the Enclave revived event emitted by the 'Executors' contract
                    Some(&ExecutorsContract::ExecutorRevived::SIGNATURE_HASH) => {
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
                            U256::ZERO,
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

    println!("Both the 'Jobs' and 'Executors' subscription streams have ended!");
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn registration_status_test() {
        let owner = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);

        assert_eq!(
            registration_status(Address::ZERO, false, owner),
            OnChainRegistration::NotRegistered
        );
        assert_eq!(
            registration_status(Address::ZERO, true, owner),
            OnChainRegistration::NotRegistered
        );
        assert_eq!(
            registration_status(owner, false, owner),
            OnChainRegistration::Registered { draining: false }
        );
        assert_eq!(
            registration_status(owner, true, owner),
            OnChainRegistration::Registered { draining: true }
        );
        assert_eq!(
            registration_status(other, false, owner),
            OnChainRegistration::OwnerMismatch(other)
        );
    }

    #[test]
    fn next_retry_delay_test() {
        let mut delay = Duration::ZERO;
        let mut delays = vec![];
        for _ in 0..9 {
            delay = next_retry_delay(delay);
            delays.push(delay.as_secs());
        }
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }
}
