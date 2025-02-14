use std::cmp::min;
use std::collections::VecDeque;
use std::pin::pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use ethers::abi::{decode, ParamType};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use ethers::types::{BigEndianHash, Filter, Log, TransactionRequest, H256, U256, U64};
use ethers::utils::keccak256;
use scopeguard::defer;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tokio_stream::Stream;

use crate::constant::{
    EXECUTION_ENV_ID, GAS_LIMIT_BUFFER, HTTP_CALL_RETRY_DELAY, RESEND_GAS_PRICE_INCREMENT_PERCENT,
    RESEND_TXN_INTERVAL,
};
use crate::job_handler::handle_job;
use crate::model::{AppState, JobsTxnMetadata, JobsTxnSendError, PendingTxnData};
use crate::timeout_handler::handle_timeout;
use crate::utils::{estimate_gas_and_price, generate_txn, parse_send_error};

// Start listening to Job requests emitted by the Jobs contract if enclave is registered else listen for Executor registered events first
pub async fn events_listener(app_state: State<AppState>, starting_block: U64) {
    defer! {
        *app_state.events_listener_active.lock().unwrap() = false;
    }
    loop {
        // web socket connection
        let ws_rpc_url = app_state.ws_rpc_url.read().unwrap().clone();
        let web_socket_client = match Provider::<Ws>::connect_with_reconnects(ws_rpc_url, 0).await {
            Ok(client) => client,
            Err(err) => {
                eprintln!(
                    "Failed to connect to the common chain websocket provider: {:?}",
                    err
                );
                continue;
            }
        };

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            // Create filter to listen to the 'TeeNodeRegistered' event emitted by the TeeManager contract
            let register_executor_filter = Filter::new()
                .address(app_state.tee_manager_contract_addr)
                .topic0(H256::from(keccak256(
                    "TeeNodeRegistered(address,address,uint256,uint256,uint8)",
                )))
                .topic1(H256::from(app_state.enclave_address))
                .topic2(H256::from(*app_state.enclave_owner.lock().unwrap()))
                .from_block(starting_block);

            // Subscribe to the TeeManager filter through the rpc web socket client
            let mut register_stream = match web_socket_client
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
                    continue;
                }
            };

            while let Some(event) = register_stream.next().await {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                app_state.enclave_registered.store(true, Ordering::SeqCst);
                app_state.last_block_seen.store(
                    event.block_number.unwrap_or(starting_block).as_u64(),
                    Ordering::SeqCst,
                );
                break;
            }

            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                continue;
            }
        }

        println!("Enclave registered successfully on the common chain!");
        // Create filter to listen to JobCreated events emitted by the Jobs contract for executor's environment
        let jobs_created_filter = Filter::new()
            .address(app_state.jobs_contract_addr)
            .topic0(H256::from(keccak256(
                "JobCreated(uint256,uint8,address,uint256,bytes32,bytes,uint256,address[])",
            )))
            .topic2(H256::from_uint(&EXECUTION_ENV_ID.into()))
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
        let jobs_created_stream = pin!(jobs_created_stream);

        // Create filter to listen to JobResponded events emitted by the Jobs contract
        let jobs_responded_filter = Filter::new()
            .address(app_state.jobs_contract_addr)
            .topic0(H256::from(keccak256(
                "JobResponded(uint256,address,bytes,uint256,uint8,uint8)",
            )))
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
        let jobs_responded_stream = pin!(jobs_responded_stream);

        // Create filter to listen to 'TeeNodeDeregistered' event emitted by the TeeManager contract
        let executor_deregistered_filter = Filter::new()
            .address(app_state.tee_manager_contract_addr)
            .topic0(H256::from(keccak256("TeeNodeDeregistered(address)")))
            .topic1(H256::from(app_state.enclave_address))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the TeeManager filter through the rpc web socket client
        let executor_deregistered_stream = match web_socket_client
            .subscribe_logs(&executor_deregistered_filter)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to TeeManager ({:?}) contract 'TeeNodeDeregistered' event logs: {:?}",
                    app_state.tee_manager_contract_addr,
                    err
                );
                continue;
            }
        };
        let executor_deregistered_stream = pin!(executor_deregistered_stream);

        // Create tokio mpsc channel to receive contract events and send transactions to them and initialize the pending txns queue to be monitored
        let (tx, rx) = channel::<JobsTxnMetadata>(100);
        let pending_txns: Arc<Mutex<VecDeque<PendingTxnData>>> = Arc::new(VecDeque::new().into());

        // Spawn task for monitoring pending transactions for block confirmation and retrying when necessary
        let app_state_clone = app_state.clone();
        let pending_txns_clone = pending_txns.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            resend_pending_transaction(app_state_clone, pending_txns_clone, tx_clone).await;
        });

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            send_execution_output(app_state_clone, rx, pending_txns).await;
        });

        handle_event_logs(
            jobs_created_stream,
            jobs_responded_stream,
            executor_deregistered_stream,
            app_state.clone(),
            tx,
        )
        .await;
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }
    }
}

// Receive job execution responses and send the resulting transactions to the common chain
async fn send_execution_output(
    app_state: State<AppState>,
    mut rx: Receiver<JobsTxnMetadata>,
    pending_txns: Arc<Mutex<VecDeque<PendingTxnData>>>,
) {
    while let Some(job_response) = rx.recv().await {
        // Initialize the txn object to send based on the txn type
        let jobs_txn = generate_txn(
            &app_state.jobs_contract_abi,
            app_state.jobs_contract_addr,
            &job_response,
        )
        .unwrap();

        // Initialize retry metadata like gas price, gas limit and the need to update the nonce from the rpc
        let mut update_nonce = false;
        let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
        let Some((mut gas_limit, mut gas_price)) = estimate_gas_and_price(
            http_rpc_client,
            &jobs_txn,
            job_response.gas_estimate_block,
            job_response.retry_deadline,
        )
        .await
        else {
            // If failed to retrieve gas limit and price for the txn under the deadline, then skip this txn
            continue;
        };

        // Retry loop for sending the transaction to the common chain 'Jobs' contract
        while Instant::now() < job_response.retry_deadline {
            // Initialize the signer rpc client being used for sending the transaction in this retry loop
            let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
            let mut txn = jobs_txn.clone();

            // If required retrieve the current nonce from the network and retry otherwise
            if update_nonce == true {
                let new_nonce_to_send = http_rpc_client
                    .get_transaction_count(http_rpc_client.address(), None)
                    .await;
                let Ok(new_nonce_to_send) = new_nonce_to_send else {
                    eprintln!(
                        "Failed to fetch current nonce for the gas address ({:?}): {:?}",
                        http_rpc_client.address(),
                        new_nonce_to_send.unwrap_err()
                    );

                    sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
                    continue;
                };

                // Update the nonce in the app_state
                *app_state.nonce_to_send.lock().unwrap() = new_nonce_to_send;
                update_nonce = false;
            }

            // Current nonce to use for sending the transaction in this retry loop
            let current_nonce = *app_state.nonce_to_send.lock().unwrap();

            // Update metadata to be used for sending the transaction and send it to the common chain
            let txn = txn
                .set_from(http_rpc_client.address())
                .set_nonce(current_nonce)
                .set_gas(gas_limit + GAS_LIMIT_BUFFER)
                .set_gas_price(gas_price)
                .to_owned();
            let pending_txn = http_rpc_client.send_transaction(txn, None).await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());
                eprintln!(
                    "Failed to send the execution {} transaction for job id {}: {}",
                    job_response.txn_type.as_str(),
                    job_response.job_id,
                    error_string
                );

                // Handle retry conditions based on the rpc error enum value
                match parse_send_error(error_string.to_lowercase()) {
                    JobsTxnSendError::NonceTooLow => {
                        update_nonce = true;
                        continue;
                    }
                    JobsTxnSendError::OutOfGas => {
                        gas_limit = gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    JobsTxnSendError::GasPriceLow => {
                        gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT) * gas_price / 100;
                        continue;
                    }
                    // Break in case the contract execution is failing for this txn or the gas required is way high compared to block gas limit
                    JobsTxnSendError::GasTooHigh | JobsTxnSendError::ContractExecution => break,
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            let pending_tx_hash = pending_txn.tx_hash();
            println!(
                "Execution {} transaction successfully sent for job id {} with nonce {} and hash {:?}",
                job_response.txn_type.as_str(), job_response.job_id, current_nonce, pending_tx_hash
            );

            // Add the current sent txn to the pending txns list with the signer client included (nonce is corresponding to the current signer)
            pending_txns.lock().unwrap().push_back(PendingTxnData {
                txn_hash: pending_tx_hash,
                txn_data: job_response,
                http_rpc_client: http_rpc_client.clone(),
                nonce: current_nonce,
                gas_limit: gas_limit,
                gas_price: gas_price,
                last_monitor_instant: Instant::now(),
            });

            // Increment nonce for the next transaction to send
            *app_state.nonce_to_send.lock().unwrap() += U256::one();
            break;
        }
    }

    println!("Transaction sender channel stopped!");
    return;
}

// Listen to the "Jobs" & "Executors" contract event logs and process them accordingly
pub async fn handle_event_logs(
    mut jobs_created_stream: impl Stream<Item = Log> + Unpin,
    mut jobs_responded_stream: impl Stream<Item = Log> + Unpin,
    mut executor_deregistered_stream: impl Stream<Item = Log> + Unpin,
    app_state: State<AppState>,
    tx: Sender<JobsTxnMetadata>,
) {
    println!("Started listening to job events!");

    loop {
        select! {
            Some(event) = executor_deregistered_stream.next() => {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                // Capture the Executor deregistered event emitted by the executors contract
                println!("Enclave deregistered from the common chain!");
                app_state.enclave_registered.store(false, Ordering::SeqCst);

                println!("Stopped listening to job events!");
                return;
            }
            // Capture the Job created event emitted by the jobs contract
            Some(event) = jobs_created_stream.next() => {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                let Some(current_block) = event.block_number else {
                    continue;
                };

                if current_block.as_u64() < app_state.last_block_seen.load(Ordering::SeqCst) {
                    continue;
                }
                app_state.last_block_seen.store(current_block.as_u64(), Ordering::SeqCst);

                // Extract the 'indexed' parameter of the event
                let job_id = event.topics[1].into_uint();

                // Extract the 'indexed' env ID and check if it's the same as executor's
                let env_id = event.topics[2].into_uint();
                if env_id != EXECUTION_ENV_ID.into() {
                    continue;
                }

                // Decode the event parameters using the ABI information
                let event_tokens = decode(
                    &vec![
                        ParamType::Uint(256),
                        ParamType::FixedBytes(32),
                        ParamType::Bytes,
                        ParamType::Uint(256),
                        ParamType::Array(Box::new(ParamType::Address)),
                    ],
                    &event.data.to_vec(),
                );
                let Ok(event_tokens) = event_tokens else {
                    eprintln!(
                        "Failed to decode 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens.unwrap_err()
                    );
                    continue;
                };

                let Some(secret_id) = event_tokens[0].clone().into_uint() else {
                    eprintln!(
                        "Failed to decode secretId token from the 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[0]
                    );
                    continue;
                };

                let Some(code_hash) = event_tokens[1].clone().into_fixed_bytes() else {
                    eprintln!(
                        "Failed to decode codeHash token from the 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[1]
                    );
                    continue;
                };
                let Some(code_inputs) = event_tokens[2].clone().into_bytes() else {
                    eprintln!(
                        "Failed to decode codeInputs token from the 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[2]
                    );
                    continue;
                };
                let Some(user_deadline) = event_tokens[3].clone().into_uint() else {
                    eprintln!(
                        "Failed to decode deadline token from the 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[3]
                    );
                    continue;
                };
                let Some(selected_nodes) = event_tokens[4].clone().into_array() else {
                    eprintln!(
                        "Failed to decode selectedExecutors token from the 'JobCreated' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[4]
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
                let is_node_selected = selected_nodes
                    .into_iter()
                    .map(|token| token.into_address())
                    .filter(|addr| addr.is_some())
                    .any(|addr| addr.unwrap() == app_state.enclave_address);

                let app_state_clone = app_state.clone();
                let tx_clone = tx.clone();

                tokio::spawn(async move {
                    handle_timeout(job_id, user_deadline.as_u64(), app_state_clone, tx_clone).await;
                });

                if is_node_selected {
                    let code_hash =
                        String::from("0x".to_owned() + &data_encoding::HEXLOWER.encode(&code_hash));
                    let app_state_clone = app_state.clone();
                    let tx_clone = tx.clone();

                    tokio::spawn(async move {
                        handle_job(
                            job_id,
                            secret_id,
                            code_hash,
                            code_inputs.into(),
                            user_deadline.as_u64(),
                            current_block.as_u64(),
                            app_state_clone,
                            tx_clone,
                        )
                        .await;
                    });
                }
            }
            // Capture the Job responded event emitted by the Jobs contract
            Some(event) = jobs_responded_stream.next() => {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                let Some(current_block) = event.block_number else {
                    continue;
                };

                if current_block.as_u64() < app_state.last_block_seen.load(Ordering::SeqCst) {
                    continue;
                }
                app_state.last_block_seen.store(current_block.as_u64(), Ordering::SeqCst);

                let job_id = event.topics[1].into_uint();

                // Decode the event parameters using the ABI information
                let event_tokens = decode(
                    &vec![
                        ParamType::Bytes,
                        ParamType::Uint(256),
                        ParamType::Uint(8),
                        ParamType::Uint(8),
                    ],
                    &event.data.to_vec(),
                );
                let Ok(event_tokens) = event_tokens else {
                    eprintln!(
                        "Failed to decode 'JobResponded' event data for job id {}: {:?}",
                        job_id,
                        event_tokens.unwrap_err()
                    );
                    continue;
                };

                let Some(output_count) = event_tokens[3].clone().into_uint() else {
                    eprintln!(
                        "Failed to decode outputCount token from the 'JobResponded' event data for job id {}: {:?}",
                        job_id,
                        event_tokens[3]
                    );
                    continue;
                };

                if output_count == app_state.num_selected_executors.into() {
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

    println!("Both the Jobs and Executors subscription streams have ended!");
}

// Function to regularly check the pending transactions for block confirmation and resend them if not included within an interval
async fn resend_pending_transaction(
    app_state: State<AppState>,
    pending_txns: Arc<Mutex<VecDeque<PendingTxnData>>>,
    tx_sender: Sender<JobsTxnMetadata>,
) {
    loop {
        let Some(mut pending_txn_data) = pending_txns.lock().unwrap().pop_front() else {
            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                // EXit if the executor has been deregistered
                return;
            }

            // Continue if the pending txns deque is empty
            sleep(Duration::from_millis(200)).await;
            continue;
        };

        // Calculate the interval to wait before checking for block confirmation of the pending txn and resending accordingly
        let resend_interval = RESEND_TXN_INTERVAL
            - min(
                RESEND_TXN_INTERVAL,
                pending_txn_data.last_monitor_instant.elapsed().as_secs(),
            );

        // Wait for the interval estimated, keeping track of the txn retry deadline as well
        sleep(Duration::from_secs(min(
            resend_interval,
            pending_txn_data
                .txn_data
                .retry_deadline
                .duration_since(Instant::now())
                .as_secs(),
        )))
        .await;

        // Get the transaction receipt for the pending transaction to check if it's still pending or been dropped
        if Retry::spawn(
            ExponentialBackoff::from_millis(5).map(jitter).take(3),
            || async {
                pending_txn_data
                    .http_rpc_client
                    .get_transaction_receipt(pending_txn_data.txn_hash)
                    .await
            },
        )
        .await
        .is_ok_and(|receipt| receipt.is_some())
        {
            // Continue the outer loop if the txn has been mined and confirmed
            continue;
        }

        // Current pending txn needs to be resent now since it still can't be confirmed and the further txns are blocked

        // Flag to keep track of whether there is a need to send dummy txn or not
        let mut send_dummy = true;
        // Increment the gas limit and price for the replacement txn to be accepted
        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
        pending_txn_data.gas_price =
            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT) * pending_txn_data.gas_price / 100;

        while Instant::now() < pending_txn_data.txn_data.retry_deadline {
            // Initialize the pending transaction data and update its metadata accordingly
            let mut replacement_txn = generate_txn(
                &app_state.jobs_contract_abi,
                app_state.jobs_contract_addr,
                &pending_txn_data.txn_data,
            )
            .unwrap();

            // Check if the gas account has been updated and therefore send the replacement transaction to the main sender
            let current_gas_address = app_state
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address();
            if current_gas_address != pending_txn_data.http_rpc_client.address() {
                send_dummy = false;
                let Ok(_) = tx_sender.send(pending_txn_data.txn_data.clone()).await else {
                    continue;
                };
                break;
            }

            let replacement_txn = replacement_txn
                .set_from(pending_txn_data.http_rpc_client.address())
                .set_nonce(pending_txn_data.nonce)
                .set_gas(pending_txn_data.gas_limit)
                .set_gas_price(pending_txn_data.gas_price)
                .to_owned();

            // Send the replacement transaction for the current nonce
            let pending_txn = pending_txn_data
                .http_rpc_client
                .send_transaction(replacement_txn, None)
                .await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());

                // Handle retry logic based on the error enum value
                match parse_send_error(error_string.to_lowercase()) {
                    JobsTxnSendError::NonceTooLow => {
                        // Current nonce is already mined and need not be resent now
                        send_dummy = false;
                        break;
                    }
                    JobsTxnSendError::OutOfGas => {
                        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    JobsTxnSendError::GasPriceLow => {
                        pending_txn_data.gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT)
                                * pending_txn_data.gas_price
                                / 100;
                        continue;
                    }
                    // Just to be on the safer side, though very less likely to occur because the same txn has been sent successfully once
                    JobsTxnSendError::GasTooHigh | JobsTxnSendError::ContractExecution => break,
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            // Monitor the newly sent pending txn
            pending_txn_data.txn_hash = pending_txn.tx_hash();
            pending_txn_data.last_monitor_instant = Instant::now();
            pending_txns
                .lock()
                .unwrap()
                .push_front(pending_txn_data.clone());

            send_dummy = false;
            break;
        }

        // Continue in case the replacement txn was sent successfully or the original pending txn was mined
        if send_dummy == false {
            continue;
        }

        eprintln!("Failed to resolve a pending txn with hash: {:?}, 
            sending 0 ETH to self (dummy txn) from the gas account for unblocking the current nonce {}", 
            pending_txn_data.txn_hash, pending_txn_data.nonce);

        // If the current nonce has still not been resolved for the 'Jobs' txn within the deadline then send a dummy txn to unblock it
        loop {
            // Check if the gas account has been updated and therefore no need to unblock the current nonce for the old gas address
            let current_gas_address = app_state
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address();
            if current_gas_address != pending_txn_data.http_rpc_client.address() {
                break;
            }

            // Send 0 ETH to self as a dummy replacement txn for the current nonce
            let dummy_replacement_txn =
                TransactionRequest::pay(pending_txn_data.http_rpc_client.address(), 0u64)
                    .nonce(pending_txn_data.nonce)
                    .gas(pending_txn_data.gas_limit)
                    .gas_price(pending_txn_data.gas_price);

            let pending_txn = pending_txn_data
                .http_rpc_client
                .send_transaction(dummy_replacement_txn, None)
                .await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());
                eprintln!(
                    "Failed to send the dummy replacement txn for the nonce {}: {}",
                    pending_txn_data.nonce, error_string
                );

                // Handle retry logic for the dummy txn
                match parse_send_error(error_string.to_lowercase()) {
                    JobsTxnSendError::NonceTooLow => {
                        // Txn mined for the current nonce and hence no need to retry
                        break;
                    }
                    JobsTxnSendError::OutOfGas => {
                        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    JobsTxnSendError::GasPriceLow => {
                        pending_txn_data.gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT)
                                * pending_txn_data.gas_price
                                / 100;
                        continue;
                    }
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            // Wait for confirmation of the sent txn
            let Ok(Some(_)) = pending_txn
                .confirmations(1)
                .interval(Duration::from_secs(1))
                .await
            else {
                // Retry if the txn is not confirmed
                continue;
            };

            // Break if the txn is successfully confirmed
            break;
        }
    }
}
