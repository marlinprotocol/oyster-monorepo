use std::collections::HashSet;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::hex;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use scopeguard::defer;
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::{interval, sleep, timeout};
use tokio_stream::{Stream, StreamExt};

use crate::constant::{
    EXECUTION_ENV_ID, LOGS_SWEEP_INTERVAL_SECS, PROCESSED_LOGS_RETAIN_BLOCKS,
    REGISTRATION_CHECK_INTERVAL_SECS, RPC_ERROR_MAX_RETRY_DELAY_SECS, RPC_ERROR_RETRY_DELAY_SECS,
    RPC_REQUEST_RETRIES, RPC_REQUEST_TIMEOUT_SECS, TIMEOUT_TXN_SEND_BUFFER_MS,
};
use crate::execution::handle_job;
use crate::model::JobsContract::slashOnExecutionTimeoutCall;
use crate::model::{AppState, ExecutorsContract, JobsContract, JobsTransaction};
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
            .topic2(B256::from(&get_byte_slice(EXECUTION_ENV_ID)));
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
            .event(JobsContract::JobResponded::SIGNATURE);
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
            .topic1(B256::from(app_state.enclave_signer.address().into_word()));
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

        let (tx, rx) = channel::<JobsTransaction>(100);

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            send_transaction(app_state_clone, rx).await;
        });

        // The subscriptions only deliver logs emitted from now on, fetch the logs emitted since the last
        // processed block (e.g. while the web socket was reconnecting). Logs delivered both ways are
        // processed once.
        match sweep_logs(&web_socket_client, &app_state, &tx).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                eprintln!(
                    "Failed to fetch the missed 'Jobs' and 'Executors' event logs: {:?}",
                    err
                );
                continue;
            }
        }
        retry_delay = Duration::from_secs(RPC_ERROR_RETRY_DELAY_SECS);

        // The web socket provider reconnects and re-subscribes on its own, without ending the streams, so
        // keep fetching the logs periodically as well
        select! {
            _ = handle_event_logs(
                jobs_created_stream,
                jobs_responded_stream,
                executors_stream,
                app_state.clone(),
                tx.clone(),
            ) => {}
            _ = periodic_sweep(&web_socket_client, &app_state, &tx) => {}
        }

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
                if !process_log(LogKind::Executors, event, &app_state, &tx_sender) {
                    println!("Stopped listening to 'Jobs' events!");
                    return;
                }
            }
            // Capture the Job created event emitted by the jobs contract
            Some(event) = jobs_created_stream.next() => {
                process_log(LogKind::JobCreated, event, &app_state, &tx_sender);
            }
            // Capture the Job responded event emitted by the Jobs contract
            Some(event) = jobs_responded_stream.next() => {
                process_log(LogKind::JobResponded, event, &app_state, &tx_sender);
            }
            else => break,
        }
    }

    println!("Both the 'Jobs' and 'Executors' subscription streams have ended!");
}

// Kind of the event logs the executor acts on
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum LogKind {
    Executors,
    JobCreated,
    JobResponded,
}

// Logs already processed, by block number, log index and block hash, so that a log delivered by both the
// subscription and the 'eth_getLogs' sweep is processed once
#[derive(Debug, Default)]
pub struct ProcessedLogs {
    seen: HashSet<(u64, u64, B256)>,
    highest_block: u64,
    pruned_at_block: u64,
}

impl ProcessedLogs {
    // Record the log, returns false if it was already processed or is too old to tell
    pub fn insert(&mut self, block: u64, log_index: Option<u64>, block_hash: Option<B256>) -> bool {
        // A log without an index is not in a block yet, there is nothing to dedupe against
        let Some(log_index) = log_index else {
            return true;
        };

        if block.saturating_add(PROCESSED_LOGS_RETAIN_BLOCKS) < self.highest_block {
            return false;
        }

        if !self
            .seen
            .insert((block, log_index, block_hash.unwrap_or_default()))
        {
            return false;
        }

        if block > self.highest_block {
            self.highest_block = block;
            if block
                >= self
                    .pruned_at_block
                    .saturating_add(PROCESSED_LOGS_RETAIN_BLOCKS / 10)
            {
                let oldest = block.saturating_sub(PROCESSED_LOGS_RETAIN_BLOCKS);
                self.seen.retain(|(seen_block, _, _)| *seen_block >= oldest);
                self.pruned_at_block = block;
            }
        }

        true
    }
}

// Process an event log of the given kind, returns false once the executor is deregistered
fn process_log(
    kind: LogKind,
    event: Log,
    app_state: &State<AppState>,
    tx_sender: &Sender<JobsTransaction>,
) -> bool {
    if event.removed {
        return true;
    }

    let Some(current_block) = event.block_number else {
        return true;
    };

    if !app_state.processed_logs.lock().unwrap().insert(
        current_block,
        event.log_index,
        event.block_hash,
    ) {
        return true;
    }

    match kind {
        LogKind::Executors => handle_executors_log(event, app_state),
        LogKind::JobCreated => {
            handle_job_created_log(event, app_state, tx_sender);
            true
        }
        LogKind::JobResponded => {
            handle_job_responded_log(event, app_state);
            true
        }
    }
}

// Handle the events emitted by the 'Executors' contract for the enclave, returns false if it is deregistered
fn handle_executors_log(event: Log, app_state: &State<AppState>) -> bool {
    match event.topic0() {
        // Capture the Enclave deregistered event emitted by the 'Executors' contract
        Some(&ExecutorsContract::ExecutorDeregistered::SIGNATURE_HASH) => {
            println!("Executor deregistered from the common chain!");
            app_state.enclave_registered.store(false, Ordering::SeqCst);
            return false;
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
        None => println!("No event topic received!"),
    }
    true
}

// Handle the Job created event emitted by the jobs contract
fn handle_job_created_log(
    event: Log,
    app_state: &State<AppState>,
    tx_sender: &Sender<JobsTransaction>,
) {
    if app_state.enclave_draining.load(Ordering::SeqCst) {
        return;
    }

    if event.topics().len() < 3 {
        return;
    }

    // Extract the 'indexed' parameter of the event
    let job_id = U256::from_be_slice(event.topics()[1].as_slice());

    // Extract the 'indexed' env ID and check if it's the same as executor's
    let env_id = U256::from_be_slice(event.topics()[2].as_slice());
    if env_id != U256::from(EXECUTION_ENV_ID) {
        return;
    }

    // Decode the event parameters using the ABI information
    let event_decoded = JobsContract::JobCreated::decode_log(&event.inner, true);
    let Ok(event_decoded) = event_decoded else {
        eprintln!(
            "Failed to decode 'JobCreated' event data for job id {}: {}",
            job_id,
            event_decoded.err().unwrap()
        );
        return;
    };

    // Mark the current job as under execution
    app_state
        .job_requests_running
        .lock()
        .unwrap()
        .insert(job_id);

    // Check if the executor has been selected for the job execution
    let is_node_selected = event_decoded
        .selectedExecutors
        .clone()
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

// Handle the Job responded event emitted by the Jobs contract
fn handle_job_responded_log(event: Log, app_state: &State<AppState>) {
    if app_state.enclave_draining.load(Ordering::SeqCst) {
        return;
    }

    if event.topics().len() < 2 {
        return;
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
        return;
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

// Kind of a log returned by the 'eth_getLogs' sweep, None for logs the executor does not act on (e.g. the
// 'Executors' events of other enclaves)
pub(crate) fn classify_log(
    log: &Log,
    jobs_contract_addr: Address,
    executors_contract_addr: Address,
    enclave_addr: Address,
) -> Option<LogKind> {
    let topic0 = *log.topic0()?;

    if log.address() == jobs_contract_addr {
        if topic0 == JobsContract::JobCreated::SIGNATURE_HASH {
            return Some(LogKind::JobCreated);
        }
        if topic0 == JobsContract::JobResponded::SIGNATURE_HASH {
            return Some(LogKind::JobResponded);
        }
    } else if log.address() == executors_contract_addr
        && (topic0 == ExecutorsContract::ExecutorDeregistered::SIGNATURE_HASH
            || topic0 == ExecutorsContract::ExecutorDrained::SIGNATURE_HASH
            || topic0 == ExecutorsContract::ExecutorRevived::SIGNATURE_HASH)
        && log.topics().get(1) == Some(&enclave_addr.into_word())
    {
        return Some(LogKind::Executors);
    }

    None
}

// Inclusive block ranges of at most 'chunk_size' blocks covering 'from..=to'
pub(crate) fn block_ranges(from: u64, to: u64, chunk_size: u64) -> Vec<(u64, u64)> {
    let chunk_size = chunk_size.max(1);
    let mut ranges = Vec::new();
    let mut start = from;
    while start <= to {
        let end = start.saturating_add(chunk_size - 1).min(to);
        ranges.push((start, end));
        if end == u64::MAX {
            break;
        }
        start = end + 1;
    }
    ranges
}

// Run an RPC request with a timeout, retrying with backoff up to RPC_REQUEST_RETRIES attempts
async fn rpc_with_retries<T, E, F, Fut>(description: &str, request: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut retry_delay = Duration::ZERO;
    let mut last_error = String::new();
    for _ in 0..RPC_REQUEST_RETRIES {
        sleep(retry_delay).await;
        retry_delay = next_retry_delay(retry_delay);

        match timeout(Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS), request()).await {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(err)) => last_error = format!("{:?}", err),
            Err(_) => last_error = String::from("request timed out"),
        }
    }

    Err(anyhow!("Failed to {}: {}", description, last_error))
}

// Fetch the 'Jobs' and 'Executors' event logs from the block after the last processed one up to the latest
// block with 'eth_getLogs' and process them in chain order. Returns false once the executor is deregistered.
async fn sweep_logs(
    provider: &impl Provider,
    app_state: &State<AppState>,
    tx_sender: &Sender<JobsTransaction>,
) -> Result<bool> {
    let latest_block = rpc_with_retries("fetch the latest block number", || {
        provider.get_block_number()
    })
    .await?;
    let from_block = app_state
        .last_block_seen
        .load(Ordering::SeqCst)
        .saturating_add(1);

    let filter = Filter::new()
        .address(vec![
            app_state.jobs_contract_addr,
            app_state.executors_contract_addr,
        ])
        .events(vec![
            JobsContract::JobCreated::SIGNATURE.as_bytes(),
            JobsContract::JobResponded::SIGNATURE.as_bytes(),
            ExecutorsContract::ExecutorDeregistered::SIGNATURE.as_bytes(),
            ExecutorsContract::ExecutorDrained::SIGNATURE.as_bytes(),
            ExecutorsContract::ExecutorRevived::SIGNATURE.as_bytes(),
        ]);

    for (start, end) in block_ranges(from_block, latest_block, app_state.logs_backfill_chunk_size) {
        let range_filter = filter.clone().from_block(start).to_block(end);
        let mut logs = rpc_with_retries(
            &format!("fetch the event logs of blocks {} to {}", start, end),
            || provider.get_logs(&range_filter),
        )
        .await?;
        logs.sort_by_key(|log| (log.block_number, log.log_index));

        for log in logs {
            let Some(kind) = classify_log(
                &log,
                app_state.jobs_contract_addr,
                app_state.executors_contract_addr,
                app_state.enclave_signer.address(),
            ) else {
                continue;
            };

            if !process_log(kind, log, app_state, tx_sender) {
                return Ok(false);
            }
        }

        app_state.last_block_seen.fetch_max(end, Ordering::SeqCst);
    }

    Ok(true)
}

// Run the 'eth_getLogs' sweep every LOGS_SWEEP_INTERVAL_SECS, returns once the executor is deregistered
async fn periodic_sweep(
    provider: &impl Provider,
    app_state: &State<AppState>,
    tx_sender: &Sender<JobsTransaction>,
) {
    loop {
        sleep(Duration::from_secs(LOGS_SWEEP_INTERVAL_SECS)).await;

        match sweep_logs(provider, app_state, tx_sender).await {
            Ok(true) => {}
            Ok(false) => {
                println!("Stopped listening to 'Jobs' events!");
                return;
            }
            Err(err) => eprintln!(
                "Failed to fetch the 'Jobs' and 'Executors' event logs: {:?}",
                err
            ),
        }
    }
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

    #[test]
    fn block_ranges_test() {
        assert_eq!(block_ranges(1, 0, 10), vec![]);
        assert_eq!(block_ranges(5, 5, 10), vec![(5, 5)]);
        assert_eq!(block_ranges(1, 10, 10), vec![(1, 10)]);
        assert_eq!(block_ranges(1, 11, 10), vec![(1, 10), (11, 11)]);
        assert_eq!(
            block_ranges(100, 30000, 10000),
            vec![(100, 10099), (10100, 20099), (20100, 30000)]
        );
        // A chunk size of zero still makes progress
        assert_eq!(block_ranges(1, 3, 0), vec![(1, 1), (2, 2), (3, 3)]);
        assert_eq!(
            block_ranges(u64::MAX - 1, u64::MAX, 10),
            vec![(u64::MAX - 1, u64::MAX)]
        );
    }

    #[test]
    fn processed_logs_test() {
        let hash_a = B256::repeat_byte(0xaa);
        let hash_b = B256::repeat_byte(0xbb);
        let mut processed = ProcessedLogs::default();

        assert!(processed.insert(10, Some(0), Some(hash_a)));
        assert!(processed.insert(10, Some(1), Some(hash_a)));
        // Same log again, e.g. from both the subscription and the sweep
        assert!(!processed.insert(10, Some(0), Some(hash_a)));
        assert!(!processed.insert(10, Some(1), Some(hash_a)));
        // Same position in a different block after a reorg
        assert!(processed.insert(10, Some(0), Some(hash_b)));
        // Logs without an index are always processed
        assert!(processed.insert(10, None, None));
        assert!(processed.insert(10, None, None));
        // Older blocks within the retained window are still accepted once
        assert!(processed.insert(9, Some(3), Some(hash_a)));
        assert!(!processed.insert(9, Some(3), Some(hash_a)));

        // Moving far ahead prunes the old entries, logs older than the window are skipped
        let far = 10 + PROCESSED_LOGS_RETAIN_BLOCKS + 1;
        assert!(processed.insert(far, Some(0), Some(hash_a)));
        assert!(!processed.seen.iter().any(|(block, _, _)| *block < 11));
        assert!(!processed.insert(10, Some(5), Some(hash_a)));
        assert!(processed.insert(far - PROCESSED_LOGS_RETAIN_BLOCKS, Some(0), Some(hash_a)));
    }

    fn log_with(address: Address, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address,
                data: alloy::primitives::LogData::new(topics, Default::default()).unwrap(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn classify_log_test() {
        let jobs = Address::repeat_byte(0x01);
        let executors = Address::repeat_byte(0x02);
        let enclave = Address::repeat_byte(0x03);
        let other_enclave = Address::repeat_byte(0x04);
        let classify = |log: &Log| classify_log(log, jobs, executors, enclave);

        let job_created = log_with(
            jobs,
            vec![
                JobsContract::JobCreated::SIGNATURE_HASH,
                B256::ZERO,
                B256::ZERO,
                B256::ZERO,
            ],
        );
        assert_eq!(classify(&job_created), Some(LogKind::JobCreated));
        let job_responded = log_with(
            jobs,
            vec![
                JobsContract::JobResponded::SIGNATURE_HASH,
                B256::ZERO,
                B256::ZERO,
            ],
        );
        assert_eq!(classify(&job_responded), Some(LogKind::JobResponded));

        for signature in [
            ExecutorsContract::ExecutorDeregistered::SIGNATURE_HASH,
            ExecutorsContract::ExecutorDrained::SIGNATURE_HASH,
            ExecutorsContract::ExecutorRevived::SIGNATURE_HASH,
        ] {
            let own = log_with(executors, vec![signature, enclave.into_word()]);
            assert_eq!(classify(&own), Some(LogKind::Executors));
            let other = log_with(executors, vec![signature, other_enclave.into_word()]);
            assert_eq!(classify(&other), None);
            let no_enclave = log_with(executors, vec![signature]);
            assert_eq!(classify(&no_enclave), None);
        }

        // Event from the wrong contract or without topics
        let wrong_contract = log_with(
            executors,
            vec![
                JobsContract::JobCreated::SIGNATURE_HASH,
                B256::ZERO,
                B256::ZERO,
            ],
        );
        assert_eq!(classify(&wrong_contract), None);
        assert_eq!(classify(&log_with(jobs, vec![])), None);
    }

    // Contract that emits a log with the 3 topics and the data given in the calldata:
    // CALLDATACOPY(0, 0x60, CALLDATASIZE - 0x60); LOG3(0, CALLDATASIZE - 0x60, cd[0], cd[0x20], cd[0x40])
    const LOG_EMITTER_INITCODE: &str =
        "601a600c600039601a6000f3606036036060600037604035602035600035606036036000a300";

    // Integration test of the 'eth_getLogs' sweep against a local Anvil chain, skipped if 'anvil' is not
    // available (set ANVIL_BIN to its path or put it on PATH)
    #[tokio::test]
    async fn sweep_logs_anvil_test() {
        use alloy::network::{EthereumWallet, TransactionBuilder};
        use alloy::primitives::Bytes;
        use alloy::rpc::types::TransactionRequest;
        use alloy::sol_types::SolValue;
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::sync::{Arc, Mutex, RwLock};

        use crate::cgroups::Cgroups;
        use alloy::signers::local::PrivateKeySigner;

        let anvil_bin = std::env::var("ANVIL_BIN").unwrap_or(String::from("anvil"));
        let port = 20000 + (std::process::id() % 20000) as u16;
        let Ok(anvil) = std::process::Command::new(&anvil_bin)
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(std::process::Stdio::null())
            .spawn()
        else {
            println!("Skipping the Anvil test, '{}' not found", anvil_bin);
            return;
        };
        let mut anvil = scopeguard::guard(anvil, |mut anvil| {
            let _ = anvil.kill();
            let _ = anvil.wait();
        });
        let _ = &mut anvil;

        // Anvil's first default account
        let deployer: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let rpc_url: reqwest::Url = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer))
            .on_http(rpc_url);
        let mut ready = false;
        for _ in 0..100 {
            if provider.get_block_number().await.is_ok() {
                ready = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "Anvil did not start");

        let deploy = || async {
            provider
                .send_transaction(
                    TransactionRequest::default()
                        .with_deploy_code(hex::decode(LOG_EMITTER_INITCODE).unwrap()),
                )
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap()
                .contract_address
                .unwrap()
        };
        let jobs = deploy().await;
        let executors = deploy().await;

        let enclave_signer = PrivateKeySigner::random();
        let enclave = enclave_signer.address();
        let other_enclave = Address::repeat_byte(0x44);

        let app_state = State(AppState {
            cgroups: Arc::new(Mutex::new(Cgroups { free: vec![] })),
            job_capacity: 1,
            workerd_runtime_path: String::new(),
            secret_store_path: String::new(),
            execution_buffer_time: 10,
            common_chain_id: 31337,
            http_rpc_url: String::new(),
            ws_rpc_url: Arc::new(RwLock::new(String::new())),
            executors_contract_addr: executors,
            jobs_contract_addr: jobs,
            code_contract_addr: String::new(),
            num_selected_executors: 1,
            enclave_signer,
            immutable_params_injected: Arc::new(Mutex::new(true)),
            mutable_params_injected: Arc::new(Mutex::new(true)),
            enclave_registered: Arc::new(AtomicBool::new(true)),
            events_listener_active: Arc::new(Mutex::new(true)),
            enclave_draining: Arc::new(AtomicBool::new(false)),
            enclave_owner: Arc::new(Mutex::new(Address::ZERO)),
            http_rpc_txn_manager: Arc::new(Mutex::new(None)),
            last_block_seen: Arc::new(AtomicU64::new(provider.get_block_number().await.unwrap())),
            // Small chunks so that every sweep spans several 'eth_getLogs' queries
            logs_backfill_chunk_size: 2,
            processed_logs: Arc::new(Mutex::new(ProcessedLogs::default())),
            job_requests_running: Arc::new(Mutex::new(HashSet::new())),
        });
        let (tx, _rx) = channel::<JobsTransaction>(10);

        let emit = |to: Address, topics: [B256; 3], data: Vec<u8>| {
            let provider = &provider;
            async move {
                let mut calldata = topics.concat();
                calldata.extend(data);
                provider
                    .send_transaction(
                        TransactionRequest::default()
                            .with_to(to)
                            .with_input(Bytes::from(calldata)),
                    )
                    .await
                    .unwrap()
                    .get_receipt()
                    .await
                    .unwrap();
            }
        };
        let job_responded = |job_id: u64| {
            (
                [
                    JobsContract::JobResponded::SIGNATURE_HASH,
                    B256::from(U256::from(job_id)),
                    B256::from(enclave.into_word()),
                ],
                (Bytes::new(), U256::ONE, U256::ZERO, U256::ONE).abi_encode_params(),
            )
        };
        let executor_event = |signature: B256, enclave: Address| {
            [signature, B256::from(enclave.into_word()), B256::ZERO]
        };

        // Logs emitted while nothing is listening: a response for job 7, the same event from the wrong
        // contract for job 8 and a drain of another enclave
        app_state
            .job_requests_running
            .lock()
            .unwrap()
            .extend([U256::from(7), U256::from(8)]);
        let (topics, data) = job_responded(7);
        emit(jobs, topics, data).await;
        let (topics, data) = job_responded(8);
        emit(executors, topics, data).await;
        emit(
            executors,
            executor_event(
                ExecutorsContract::ExecutorDrained::SIGNATURE_HASH,
                other_enclave,
            ),
            vec![],
        )
        .await;

        assert!(sweep_logs(&provider, &app_state, &tx).await.unwrap());
        let head = provider.get_block_number().await.unwrap();
        assert_eq!(app_state.last_block_seen.load(Ordering::SeqCst), head);
        assert!(!app_state
            .job_requests_running
            .lock()
            .unwrap()
            .contains(&U256::from(7)));
        assert!(app_state
            .job_requests_running
            .lock()
            .unwrap()
            .contains(&U256::from(8)));
        assert!(!app_state.enclave_draining.load(Ordering::SeqCst));

        // Drain and revive in consecutive blocks, the sweep processes them in chain order
        emit(
            executors,
            executor_event(ExecutorsContract::ExecutorDrained::SIGNATURE_HASH, enclave),
            vec![],
        )
        .await;
        emit(
            executors,
            executor_event(ExecutorsContract::ExecutorRevived::SIGNATURE_HASH, enclave),
            vec![],
        )
        .await;
        assert!(sweep_logs(&provider, &app_state, &tx).await.unwrap());
        assert!(!app_state.enclave_draining.load(Ordering::SeqCst));

        // A sweep with no new blocks does nothing
        assert!(sweep_logs(&provider, &app_state, &tx).await.unwrap());

        // The drain log delivered again (e.g. by the subscription) is not processed a second time
        let drained_logs = provider
            .get_logs(
                &Filter::new()
                    .address(executors)
                    .event_signature(ExecutorsContract::ExecutorDrained::SIGNATURE_HASH)
                    .topic1(B256::from(enclave.into_word()))
                    .from_block(0),
            )
            .await
            .unwrap();
        assert_eq!(drained_logs.len(), 1);
        assert!(process_log(
            LogKind::Executors,
            drained_logs[0].clone(),
            &app_state,
            &tx
        ));
        assert!(!app_state.enclave_draining.load(Ordering::SeqCst));

        // Deregistration stops the sweep
        emit(
            executors,
            executor_event(
                ExecutorsContract::ExecutorDeregistered::SIGNATURE_HASH,
                enclave,
            ),
            vec![],
        )
        .await;
        assert!(!sweep_logs(&provider, &app_state, &tx).await.unwrap());
        assert!(!app_state.enclave_registered.load(Ordering::SeqCst));
    }
}
