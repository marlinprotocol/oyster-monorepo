use alloy::{
    primitives::{keccak256, Address, U256},
    rpc::types::Log,
    sol_types::SolEvent,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{sleep_until, Instant},
};
use tracing::{error, info};

use crate::{
    chain_util::{HttpProvider, HttpProviderLogs, LogsProvider},
    constant::{
        GATEWAY_BLOCK_STATES_TO_MAINTAIN, REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT,
        REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT,
        REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT,
    },
    contract_abi::RelaySubscriptionsContract,
    error::ServerlessError,
    model::{
        ContractsClient, GatewayJobType, Job, JobMode, JobSubscriptionAction,
        JobSubscriptionChannelType, RequestChainData, SubscriptionJob, SubscriptionJobInstanceHeap,
    },
};

/// Converts a Unix timestamp to an `Instant`.
///
/// If the timestamp is in the future, the function returns an `Instant` in the future.
/// If the timestamp is in the past, the function returns `Instant::now()`.
///
/// # Arguments
///
/// * `timestamp` - A Unix timestamp represented as a `u64`.
///
/// # Returns
///
/// * An `Instant` representing the given timestamp or the current time if the timestamp is in the past.
fn unix_timestamp_to_instant(timestamp: u64) -> Instant {
    let duration = Duration::from_secs(timestamp);
    let timestamp_in_system_time = UNIX_EPOCH + duration;
    Instant::now()
        + timestamp_in_system_time
            .duration_since(SystemTime::now())
            .unwrap_or_default()
}

impl PartialEq for SubscriptionJobInstanceHeap {
    fn eq(&self, other: &Self) -> bool {
        self.next_trigger_time == other.next_trigger_time
    }
}

impl Eq for SubscriptionJobInstanceHeap {}

impl PartialOrd for SubscriptionJobInstanceHeap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.next_trigger_time
                .cmp(&other.next_trigger_time)
                .reverse(),
        )
    }
}

impl Ord for SubscriptionJobInstanceHeap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.next_trigger_time
            .cmp(&other.next_trigger_time)
            .reverse()
    }
}

pub async fn process_historic_job_subscriptions(
    contracts_client: &Arc<ContractsClient>,
    req_chain_tx: Sender<Job>,
    job_sub_tx: Sender<JobSubscriptionChannelType>,
) {
    info!("Processing Historic Job Subscriptions on Request Chains");

    let request_chains_data = contracts_client.request_chains_data.read().unwrap().clone();

    for request_chain_id in contracts_client.request_chain_ids.clone() {
        let contracts_client_clone = contracts_client.clone();
        let req_chain_tx_clone = req_chain_tx.clone();

        let job_sub_tx_clone = job_sub_tx.clone();
        let request_chain_data = request_chains_data.get(&request_chain_id).unwrap().clone();
        tokio::spawn(async move {
            let http_provider = HttpProvider::new(request_chain_data.http_rpc_url.clone());
            process_historic_subscription_jobs_on_request_chain(
                &contracts_client_clone,
                &request_chain_data,
                req_chain_tx_clone,
                job_sub_tx_clone,
                http_provider,
            )
            .await;
        });
    }
}

pub async fn process_historic_subscription_jobs_on_request_chain<'a, P: HttpProviderLogs>(
    contracts_client: &Arc<ContractsClient>,
    request_chain_data: &RequestChainData,
    req_chain_tx: Sender<Job>,
    job_sub_tx: Sender<JobSubscriptionChannelType>,
    http_provider: P,
) {
    let logs = contracts_client
        .request_chain_historic_subscription_jobs(&request_chain_data, &http_provider)
        .await
        .unwrap();

    let request_chain_id = request_chain_data.chain_id;

    for log in logs {
        let topics = log.topics();

        if topics[0] == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT) {
            info!(
                "Processing Historic Job Subscription - Subscription Started - Subscription ID: {}",
                U256::from_be_slice(&topics[1].as_slice())
            );
            let sub_id = add_subscription_job(
                contracts_client,
                log,
                request_chain_id,
                req_chain_tx.clone(),
                true,
            )
            .unwrap();
            if sub_id == U256::from(0) {
                continue;
            }
            job_sub_tx
                .send(JobSubscriptionChannelType {
                    subscription_action: JobSubscriptionAction::Add,
                    subscription_id: sub_id,
                })
                .await
                .unwrap();
        } else if topics[0] == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT) {
            info!(
                "Processing Historic Job Subscription - Subscription Params Updated - Subscription ID: {}",
                U256::from_be_slice(&topics[1].as_slice())
            );
            let _ = update_subscription_job_params(contracts_client, log);
        } else if topics[0]
            == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT)
        {
            info!(
                "Processing Historic Job Subscription - Subscription Termination Params Updated - Subscription ID: {}",
                U256::from_be_slice(&topics[1].as_slice())
            );
            let _ = update_subscription_job_termination_params(contracts_client, log);
        }
    }
}

pub async fn job_subscription_manager(
    contracts_client: Arc<ContractsClient>,
    mut rx: Receiver<JobSubscriptionChannelType>,
    req_chain_tx: Sender<Job>,
) {
    loop {
        let next_trigger_time: Option<u64>;
        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            next_trigger_time = subscription_job_instance_heap_guard
                .peek()
                .map(|t| t.next_trigger_time);
        }

        tokio::select! {
            Some(job_subscription_channel_data) = rx.recv() => {
                match job_subscription_channel_data.subscription_action {
                    JobSubscriptionAction::Add => {
                        info!(
                            "Added new subscription JobSubscriptionId: {}",
                            job_subscription_channel_data.subscription_id
                        );
                    }
                }
            }
            _ = sleep_until(next_trigger_time.map(|t|
                unix_timestamp_to_instant(t)
            ).unwrap_or_else(Instant::now)), if next_trigger_time.is_some() => {
                let contracts_client_clone = contracts_client.clone();
                let subscription_job_instance: Option<SubscriptionJobInstanceHeap>;
                {
                    let mut subscription_job_instance_heap_guard = contracts_client.subscription_job_instance_heap
                        .write()
                        .unwrap();
                    subscription_job_instance = subscription_job_instance_heap_guard.pop();
                }

                if subscription_job_instance.is_none() {
                    error!("Subscription Job Triggered but no subscription found");
                    continue;
                }
                let subscription_job_instance = subscription_job_instance.unwrap();

                let req_chain_tx_clone = req_chain_tx.clone();

                let subscription_job: Option<SubscriptionJob>;
                // Scope for read lock on subscription_jobs
                {
                    let subscription_jobs_guard = contracts_client.subscription_jobs.read().unwrap();
                    subscription_job = subscription_jobs_guard
                        .get(&subscription_job_instance.subscription_id)
                        .cloned();
                }

                if subscription_job.is_none() {
                    info!(
                        "Job No longer active for Subscription - Subscription ID: {}",
                        subscription_job_instance.subscription_id
                    );
                    return;
                }

                tokio::spawn(async move {
                    trigger_subscription_job(
                        subscription_job.unwrap(),
                        subscription_job_instance.next_trigger_time,
                        contracts_client_clone,
                        req_chain_tx_clone
                    ).await;
                });
                add_next_trigger_time_to_heap(
                    &contracts_client,
                    subscription_job_instance.subscription_id.clone(),
                    subscription_job_instance.next_trigger_time,
                    false,
                );
            }
            else => {
                info!("Awaiting");
                // do nothing
            }
        }
    }
}

pub fn add_subscription_job(
    contracts_client: &Arc<ContractsClient>,
    subscription_log: Log,
    request_chain_id: u64,
    req_chain_tx: Sender<Job>,
    is_historic_log: bool,
) -> Result<U256, ServerlessError> {
    let job_subscription_started_event_decoded =
        RelaySubscriptionsContract::JobSubscriptionStarted::decode_log(
            &subscription_log.inner,
            true,
        );

    if job_subscription_started_event_decoded.is_err() {
        error!(
            "Failed to decode subscription log: {}",
            job_subscription_started_event_decoded.err().unwrap()
        );
        return Err(ServerlessError::LogDecodeFailure);
    }

    let decoded = job_subscription_started_event_decoded.unwrap();

    let subscription_job_topics = subscription_log.topics();
    let subscriber = Address::from_slice(&subscription_job_topics[3].as_slice()[12..]);

    let subscription_job = SubscriptionJob {
        subscription_id: U256::from_be_slice(&subscription_job_topics[1].as_slice()),
        request_chain_id,
        subscriber,
        interval: decoded.periodicGap.to::<u64>(),
        termination_time: decoded.terminationTimestamp.to::<u64>(),
        user_timeout: decoded.userTimeout,
        tx_hash: decoded.codehash,
        code_input: decoded.codeInputs.clone(),
        starttime: decoded.startTime.to::<u64>(),
        env: U256::from_be_slice(&subscription_job_topics[2].as_slice()).to::<u8>(),
    };

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if is_historic_log && subscription_job.termination_time < current_timestamp {
        info!(
            "Subscription Job is complete - Subscription ID: {}",
            subscription_job.subscription_id
        );
        return Ok(U256::from(0));
    }

    // Scope for write lock on subscription_jobs
    {
        let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
        subscription_jobs.insert(subscription_job.subscription_id, subscription_job.clone());
    }

    let mut to_trigger_first_instance = true;
    if is_historic_log {
        let minimum_timestamp_for_job = get_minimum_timestamp_for_job(contracts_client);

        if subscription_job.starttime < minimum_timestamp_for_job {
            to_trigger_first_instance = false;
        }
    }

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut is_starttime_in_future = false;
    if subscription_job.starttime > current_timestamp {
        info!(
            "Subscription Job is scheduled for future - Subscription ID: {}",
            subscription_job.subscription_id
        );

        to_trigger_first_instance = false;

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_job.subscription_id,
            subscription_job.starttime - subscription_job.interval,
            is_historic_log,
        );

        is_starttime_in_future = true;
    }

    if to_trigger_first_instance {
        let contracts_client_clone = contracts_client.clone();
        let subscription_job_clone = subscription_job.clone();
        tokio::spawn(async move {
            trigger_subscription_job(
                subscription_job_clone,
                subscription_job.starttime,
                contracts_client_clone,
                req_chain_tx,
            )
            .await
        });
    }

    if !is_starttime_in_future {
        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_job.subscription_id,
            subscription_job.starttime,
            is_historic_log,
        );
    }
    Ok(subscription_job.subscription_id)
}

/// Returns the minimum timestamp for a job to be triggered w.r.t to the current time
/// and the maintained block states.
///
/// # Arguments
///
/// * `contracts_client` - A reference to the `ContractsClient`.
///
/// # Returns
///
/// * A `u64` representing the minimum timestamp for a job to be triggered.
fn get_minimum_timestamp_for_job(contracts_client: &Arc<ContractsClient>) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - ((GATEWAY_BLOCK_STATES_TO_MAINTAIN) * contracts_client.time_interval)
        - contracts_client.offset_for_epoch
}

fn add_next_trigger_time_to_heap(
    contracts_client: &Arc<ContractsClient>,
    subscription_id: U256,
    previous_trigger_time: u64,
    is_historic_log: bool,
) {
    let subscription_job = contracts_client
        .subscription_jobs
        .read()
        .unwrap()
        .get(&subscription_id)
        .cloned();

    if subscription_job.is_none() {
        error!(
            "Subscription Job not found for Subscription ID: {}",
            subscription_id
        );
        return;
    }

    let subscription_job = subscription_job.unwrap();

    let mut next_trigger_time = previous_trigger_time + subscription_job.interval;

    if next_trigger_time > subscription_job.termination_time {
        info!(
            "Subscription Job has reached termination time - Subscription ID: {}",
            subscription_job.subscription_id
        );
        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.remove(&subscription_id);
        }
        return;
    }

    if is_historic_log {
        let minimum_timestamp_for_job = get_minimum_timestamp_for_job(contracts_client);

        if next_trigger_time < minimum_timestamp_for_job {
            let instance_count = ((minimum_timestamp_for_job - subscription_job.starttime)
                / subscription_job.interval)
                + 1;

            next_trigger_time =
                subscription_job.starttime + instance_count * subscription_job.interval;
        }
    }

    // Scope for write lock on subscription_job_instance_heap
    {
        let mut subscription_job_instance_heap_guard = contracts_client
            .subscription_job_instance_heap
            .write()
            .unwrap();
        subscription_job_instance_heap_guard.push(SubscriptionJobInstanceHeap {
            subscription_id: subscription_job.subscription_id,
            next_trigger_time,
        });
    }
}

async fn trigger_subscription_job(
    subscription_job: SubscriptionJob,
    trigger_timestamp: u64,
    contracts_client: Arc<ContractsClient>,
    req_chain_tx: Sender<Job>,
) {
    info!(
        "Triggering subscription job with ID: {}",
        subscription_job.subscription_id
    );

    let job = subscription_job_to_relay_job(subscription_job, trigger_timestamp);

    contracts_client
        .job_relayed_handler(job, req_chain_tx)
        .await;
}

fn subscription_job_to_relay_job(subscription_job: SubscriptionJob, trigger_timestamp: u64) -> Job {
    let instance_count =
        (trigger_timestamp - subscription_job.starttime) / subscription_job.interval;
    let job_id = subscription_job.subscription_id + U256::from(instance_count);
    let instance_starttime =
        subscription_job.starttime + instance_count * subscription_job.interval;

    Job {
        job_id,
        request_chain_id: subscription_job.request_chain_id,
        tx_hash: subscription_job.tx_hash,
        code_input: subscription_job.code_input,
        user_timeout: subscription_job.user_timeout,
        starttime: instance_starttime,
        job_owner: subscription_job.subscriber,
        job_type: GatewayJobType::JobRelay,
        sequence_number: 1,
        gateway_address: None,
        job_mode: JobMode::Subscription,
        env: subscription_job.env,
    }
}

pub fn update_subscription_job_params(
    contracts_client: &Arc<ContractsClient>,
    subscription_log: Log,
) -> Result<(), ServerlessError> {
    let job_subscription_job_params_updated_event_decoded =
        RelaySubscriptionsContract::JobSubscriptionJobParamsUpdated::decode_log(
            &subscription_log.inner,
            true,
        );

    if job_subscription_job_params_updated_event_decoded.is_err() {
        error!(
            "Failed to decode subscription log: {}",
            job_subscription_job_params_updated_event_decoded
                .err()
                .unwrap()
        );
        return Err(ServerlessError::LogDecodeFailure);
    }

    let decoded = job_subscription_job_params_updated_event_decoded.unwrap();

    let subscription_job_topics = subscription_log.topics();
    let subscription_id = U256::from_be_slice(&subscription_job_topics[1].as_slice());

    let subscription_job = contracts_client
        .subscription_jobs
        .read()
        .unwrap()
        .get(&subscription_id)
        .cloned();

    if subscription_job.is_none() {
        error!(
            "Subscription Job not found for Subscription ID: {}",
            subscription_id
        );
        return Err(ServerlessError::NoSubscriptionJobFound(subscription_id));
    }

    let new_tx_hash = decoded.codehash;
    let new_code_input = decoded.codeInputs.clone();

    // Update the subscription job
    // Scope for write lock on subscription_jobs
    {
        let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
        let subscription_job = subscription_jobs.get_mut(&subscription_id).unwrap();
        subscription_job.tx_hash = new_tx_hash;
        subscription_job.code_input = new_code_input;
    }

    Ok(())
}

pub fn update_subscription_job_termination_params(
    contracts_client: &Arc<ContractsClient>,
    subscription_log: Log,
) -> Result<(), ServerlessError> {
    let job_subscription_termination_params_updated_event_decoded =
        RelaySubscriptionsContract::JobSubscriptionTerminationParamsUpdated::decode_log(
            &subscription_log.inner,
            true,
        );

    if job_subscription_termination_params_updated_event_decoded.is_err() {
        error!(
            "Failed to decode subscription log: {}",
            job_subscription_termination_params_updated_event_decoded
                .err()
                .unwrap()
        );
        return Err(ServerlessError::LogDecodeFailure);
    }

    let decoded = job_subscription_termination_params_updated_event_decoded.unwrap();

    let subscription_job_topics = subscription_log.topics();
    let subscription_id = U256::from_be_slice(&subscription_job_topics[1].as_slice());

    let subscription_job = contracts_client
        .subscription_jobs
        .read()
        .unwrap()
        .get(&subscription_id)
        .cloned();

    if subscription_job.is_none() {
        error!(
            "Subscription Job not found for Subscription ID: {}",
            subscription_id
        );
        return Err(ServerlessError::NoSubscriptionJobFound(subscription_id));
    }

    let new_termination_time = decoded.terminationTimestamp.to::<u64>();

    // Update the subscription job
    // Scope for write lock on subscription_jobs
    {
        let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
        let subscription_job = subscription_jobs.get_mut(&subscription_id).unwrap();
        subscription_job.termination_time = new_termination_time;
    }

    Ok(())
}

#[cfg(test)]
mod job_subscription_management_tests {
    use alloy::{
        dyn_abi::DynSolValue,
        primitives::{Bytes, Log as InnerLog, LogData},
        signers::local::PrivateKeySigner,
    };
    use serde_json::json;

    use super::*;

    use crate::test_util::{
        add_gateway_epoch_state, generate_contracts_client, generate_generic_subscription_job,
        generate_job_subscription_job_params_updated, generate_job_subscription_started_log,
        generate_job_subscription_termination_params_updated, MockHttpProvider, CHAIN_ID,
        CODE_HASH,
    };

    #[test]
    fn test_unix_timestamp_to_instant() {
        // Future time stays in future
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let instant = unix_timestamp_to_instant(timestamp);
        let instant_now = Instant::now();
        assert!(instant < instant_now + Duration::from_secs(60));
        assert!(instant > instant_now + Duration::from_secs(59));

        // Future time stays in future
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1000;
        let instant = unix_timestamp_to_instant(timestamp);
        let instant_now = Instant::now();
        assert!(instant < instant_now + Duration::from_secs(1000));
        assert!(instant > instant_now + Duration::from_secs(999));

        // Past time becomes instance now time
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100;
        let instant = unix_timestamp_to_instant(timestamp);
        let instant_now = Instant::now();
        assert!(instant < instant_now + Duration::from_secs(1));
        assert!(instant > instant_now - Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_add_subscription_job_invalid_log() {
        let contracts_client = generate_contracts_client().await;
        let request_chain_id = CHAIN_ID;
        let (req_chain_tx, _) = tokio::sync::mpsc::channel::<Job>(100);
        let is_history_log = false;

        // topics is missing the indexed event parameter jobSubscriber at index 4
        // data is missing code_input and starttime parameters
        let log = Log {
            inner: InnerLog {
                address: Address::default(),
                data: LogData::new_unchecked(
                    vec![
                        keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT).into(),
                        U256::from(1).into(),
                        U256::from(1).into(),
                    ],
                    DynSolValue::Tuple(vec![
                        DynSolValue::Uint(U256::from(10), 256),
                        DynSolValue::Uint(U256::from(1000), 256),
                        DynSolValue::Uint(U256::from(100000), 256),
                        DynSolValue::Uint(U256::from(100), 256),
                        DynSolValue::Address(PrivateKeySigner::random().address()),
                        DynSolValue::FixedBytes(*CODE_HASH, 32),
                    ])
                    .abi_encode()
                    .into(),
                ),
            },

            ..Default::default()
        };

        let res = add_subscription_job(
            &contracts_client,
            log,
            request_chain_id,
            req_chain_tx,
            is_history_log,
        );

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), ServerlessError::LogDecodeFailure);

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job = subscription_jobs.get(&U256::from(1));

            assert!(subscription_job.is_none());
        }

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek();

            assert!(subscription_job_instance.is_none());
        }

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_none());
        }
    }

    #[tokio::test]
    async fn test_add_subscription_job_historic_inactive_job() {
        let contracts_client = generate_contracts_client().await;
        let request_chain_id = CHAIN_ID;
        let (req_chain_tx, _) = tokio::sync::mpsc::channel::<Job>(100);
        let is_history_log = true;

        let log = generate_job_subscription_started_log(None, Some(-1500));

        let res = add_subscription_job(
            &contracts_client,
            log,
            request_chain_id,
            req_chain_tx,
            is_history_log,
        );

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), U256::from(0));

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job = subscription_jobs.get(&U256::from(1));

            assert!(subscription_job.is_none());
        }

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek();

            assert!(subscription_job_instance.is_none());
        }

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_none());
        }
    }

    #[tokio::test]
    async fn test_add_subscription_job_historic_active_job_with_first_instance_trigger() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-2)).await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-3)).await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-4)).await;
        let request_chain_id = CHAIN_ID;
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);
        let is_history_log = true;

        let log = generate_job_subscription_started_log(None, Some(-50));

        let res = add_subscription_job(
            &contracts_client.clone(),
            log,
            request_chain_id,
            req_chain_tx,
            is_history_log,
        );

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), U256::from(1));

        let result_subscription_job: SubscriptionJob;
        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job = subscription_jobs.get(&U256::from(1)).cloned();

            assert!(subscription_job.is_some());

            result_subscription_job = subscription_job.unwrap();

            assert_eq!(result_subscription_job.subscription_id, U256::from(1));
        }

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                result_subscription_job.starttime + result_subscription_job.interval
            );
        }

        let mut expected_job = subscription_job_to_relay_job(
            result_subscription_job.clone(),
            result_subscription_job.starttime,
        );
        expected_job.gateway_address = Some(contracts_client.enclave_address);

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_some());
            assert_eq!(active_job.unwrap(), &expected_job);
        }
    }

    #[tokio::test]
    async fn test_get_minimum_timestamp_for_job() {
        let contracts_client = generate_contracts_client().await;
        let minimum_timestamp = get_minimum_timestamp_for_job(&contracts_client);
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expected_timestamp = current_timestamp
            - (GATEWAY_BLOCK_STATES_TO_MAINTAIN * contracts_client.time_interval)
            - contracts_client.offset_for_epoch;
        assert_eq!(minimum_timestamp, expected_timestamp);
    }

    #[tokio::test]
    async fn test_add_subscription_job_historic_active_job() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-5)).await;
        let request_chain_id = CHAIN_ID;
        let (req_chain_tx, _) = tokio::sync::mpsc::channel::<Job>(100);
        let is_history_log = true;

        let log = generate_job_subscription_started_log(None, Some(-500));

        let res = add_subscription_job(
            &contracts_client.clone(),
            log,
            request_chain_id,
            req_chain_tx,
            is_history_log,
        );

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), U256::from(1));

        let result_subscription_job: SubscriptionJob;
        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job = subscription_jobs.get(&U256::from(1)).cloned();

            assert!(subscription_job.is_some());

            result_subscription_job = subscription_job.unwrap();

            assert_eq!(result_subscription_job.subscription_id, U256::from(1));
        }

        let expected_next_trigger_time = result_subscription_job.starttime
            + result_subscription_job.interval
                * (((get_minimum_timestamp_for_job(&contracts_client)
                    - result_subscription_job.starttime)
                    / result_subscription_job.interval)
                    + 1);

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                expected_next_trigger_time
            );
        }

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_none());
        }
    }

    #[tokio::test]
    async fn test_add_subscription_job_active_job() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, None).await;
        let request_chain_id = CHAIN_ID;
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);
        let is_history_log = false;

        let log = generate_job_subscription_started_log(None, None);

        let expected_subscription_job = generate_generic_subscription_job(None, None);

        let res = add_subscription_job(
            &contracts_client,
            log,
            request_chain_id,
            req_chain_tx,
            is_history_log,
        );

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(res.is_ok());

        let res = res.unwrap();
        assert_eq!(res, U256::from(1));

        let subscription_job: SubscriptionJob;
        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            subscription_job = subscription_jobs.get(&U256::from(1)).cloned().unwrap();

            assert_eq!(subscription_job, expected_subscription_job);
        }

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                expected_subscription_job.starttime + expected_subscription_job.interval
            );
        }

        let mut expected_job =
            subscription_job_to_relay_job(subscription_job.clone(), subscription_job.starttime);
        expected_job.gateway_address = Some(contracts_client.enclave_address);

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_some());
            assert_eq!(active_job.unwrap(), &expected_job);
        }
    }

    #[tokio::test]
    async fn test_add_next_trigger_time_to_heap_historic_active_job_with_first_instance_trigger() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);

        let subscription_job = generate_generic_subscription_job(None, Some(-100));

        // when is_historic_log is true, previous_trigger_time is the starttime of the job
        let is_historic_log = true;

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_id,
            subscription_job.starttime,
            is_historic_log,
        );

        let expected_next_trigger_time = subscription_job.starttime + subscription_job.interval;

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                expected_next_trigger_time
            );
        }

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_add_next_trigger_time_to_heap_historic_active_job() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);

        let subscription_job = generate_generic_subscription_job(None, Some(-500));

        // when is_historic_log is true, previous_trigger_time is the starttime of the job
        let is_historic_log = true;

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_id,
            subscription_job.starttime,
            is_historic_log,
        );

        let expected_next_trigger_time = subscription_job.starttime
            + subscription_job.interval
                * (((get_minimum_timestamp_for_job(&contracts_client)
                    - subscription_job.starttime)
                    / subscription_job.interval)
                    + 1);

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                expected_next_trigger_time
            );
        }

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_add_next_trigger_time_to_heap_job_just_added() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // when job is just added, previous_trigger_time is job starttime
        let is_historic_log = false;

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_id,
            subscription_job.starttime,
            is_historic_log,
        );

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                subscription_job.starttime + subscription_job.interval
            );
        }

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_add_next_trigger_time_to_heap_active_job() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // when is_historic_log is false, previous_trigger_time is the closest time to the current time
        let previous_trigger_time = system_time;
        let is_historic_log = false;

        let subscription_job = generate_generic_subscription_job(None, Some(-500));

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_id,
            previous_trigger_time,
            is_historic_log,
        );

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                previous_trigger_time + subscription_job.interval
            );
        }

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_add_next_trigger_time_to_heap_at_job_termination_time() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // when is_historic_log is true, previous_trigger_time is the starttime of the job
        let previous_trigger_time = system_time;
        let is_historic_log = false;

        let subscription_job = generate_generic_subscription_job(None, Some(-1000));

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        add_next_trigger_time_to_heap(
            &contracts_client,
            subscription_id,
            previous_trigger_time,
            is_historic_log,
        );

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek();

            assert!(subscription_job_instance.is_none());
        }

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job = subscription_jobs.get(&U256::from(1));

            assert!(subscription_job.is_none());
        }
    }

    #[tokio::test]
    async fn test_subscription_job_to_relay_job() {
        let subscription_job = generate_generic_subscription_job(None, None);
        let trigger_timestamp = subscription_job.starttime;

        let job = subscription_job_to_relay_job(subscription_job.clone(), trigger_timestamp);

        assert_eq!(job.job_id, subscription_job.subscription_id);
        assert_eq!(job.request_chain_id, subscription_job.request_chain_id);
        assert_eq!(job.tx_hash, subscription_job.tx_hash);
        assert_eq!(job.code_input, subscription_job.code_input);
        assert_eq!(job.user_timeout, subscription_job.user_timeout);
        assert_eq!(job.starttime, subscription_job.starttime);
        assert_eq!(job.job_owner, subscription_job.subscriber);
        assert_eq!(job.job_type, GatewayJobType::JobRelay);
        assert_eq!(job.sequence_number, 1);
        assert_eq!(job.gateway_address, None);
        assert_eq!(job.job_mode, JobMode::Subscription);

        let trigger_timestamp = subscription_job.starttime + 50;

        let job = subscription_job_to_relay_job(subscription_job.clone(), trigger_timestamp);

        assert_eq!(job.job_id, subscription_job.subscription_id + U256::from(5));
        assert_eq!(job.request_chain_id, subscription_job.request_chain_id);
        assert_eq!(job.tx_hash, subscription_job.tx_hash);
        assert_eq!(job.code_input, subscription_job.code_input);
        assert_eq!(job.user_timeout, subscription_job.user_timeout);
        assert_eq!(job.starttime, subscription_job.starttime + 50);
        assert_eq!(job.job_owner, subscription_job.subscriber);
        assert_eq!(job.job_type, GatewayJobType::JobRelay);
        assert_eq!(job.sequence_number, 1);
        assert_eq!(job.gateway_address, None);
        assert_eq!(job.job_mode, JobMode::Subscription);

        let trigger_timestamp = subscription_job.starttime + 408;

        let job = subscription_job_to_relay_job(subscription_job.clone(), trigger_timestamp);

        assert_eq!(
            job.job_id,
            subscription_job.subscription_id + U256::from(40)
        );
        assert_eq!(job.request_chain_id, subscription_job.request_chain_id);
        assert_eq!(job.tx_hash, subscription_job.tx_hash);
        assert_eq!(job.code_input, subscription_job.code_input);
        assert_eq!(job.user_timeout, subscription_job.user_timeout);
        assert_eq!(job.starttime, subscription_job.starttime + 400);
        assert_eq!(job.job_owner, subscription_job.subscriber);
        assert_eq!(job.job_type, GatewayJobType::JobRelay);
        assert_eq!(job.sequence_number, 1);
        assert_eq!(job.gateway_address, None);
        assert_eq!(job.job_mode, JobMode::Subscription);
    }

    #[tokio::test]
    async fn test_update_subscription_job_params_invalid_log() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        // data is empty
        let log = Log {
            inner: InnerLog {
                address: Address::default(),
                data: LogData::new_unchecked(
                    vec![
                        keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT).into(),
                        U256::from(1).into(),
                    ],
                    DynSolValue::Tuple(vec![]).abi_encode().into(),
                ),
            },
            ..Default::default()
        };

        let res = update_subscription_job_params(&contracts_client, log);

        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), ServerlessError::LogDecodeFailure);

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_update_subscription_job_params_subscription_job_not_found() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);

        let log = generate_job_subscription_job_params_updated(None, None, Some(104));

        let res = update_subscription_job_params(&contracts_client, log);

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ServerlessError::NoSubscriptionJobFound(subscription_id)
        );
    }

    #[tokio::test]
    async fn test_update_subscription_job_params_active_job_tx_hash_update() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        let new_code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e7d8";
        let log = generate_job_subscription_job_params_updated(None, Some(new_code_hash), None);

        let res = update_subscription_job_params(&contracts_client, log);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ());

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(result_subscription_job.tx_hash, keccak256(new_code_hash));
            assert_eq!(
                result_subscription_job.code_input,
                subscription_job.code_input
            );
        }
    }

    #[tokio::test]
    async fn test_update_subscription_job_params_active_job_code_input_update() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        let log = generate_job_subscription_job_params_updated(None, None, Some(188));

        let res = update_subscription_job_params(&contracts_client, log);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ());

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(result_subscription_job.tx_hash, subscription_job.tx_hash,);
            assert_eq!(
                result_subscription_job.code_input,
                Bytes::from(
                    serde_json::to_vec(&json!({
                        "num": 188
                    }))
                    .unwrap(),
                )
            );
        }
    }

    #[tokio::test]
    async fn test_update_subscription_job_params_active_job_all_update() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        let new_code_hash = "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e7d8";
        let log = generate_job_subscription_job_params_updated(
            None,
            Some("9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e7d8"),
            Some(188),
        );

        let res = update_subscription_job_params(&contracts_client, log);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ());

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(result_subscription_job.tx_hash, keccak256(new_code_hash));
            assert_eq!(
                result_subscription_job.code_input,
                Bytes::from(
                    serde_json::to_vec(&json!({
                        "num": 188
                    }))
                    .unwrap(),
                )
            );
        }
    }

    #[tokio::test]
    async fn test_update_subscription_job_termination_params_invalid_log() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        // data is empty
        let log = Log {
            inner: InnerLog {
                address: Address::default(),
                data: LogData::new_unchecked(
                    vec![
                        keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT)
                            .into(),
                        U256::from(1).into(),
                    ],
                    DynSolValue::Tuple(vec![]).abi_encode().into(),
                ),
            },
            ..Default::default()
        };

        let res = update_subscription_job_termination_params(&contracts_client, log);

        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), ServerlessError::LogDecodeFailure);

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(*result_subscription_job, subscription_job);
        }
    }

    #[tokio::test]
    async fn test_update_subscription_job_termination_params_subscription_job_not_found() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);

        let log = generate_job_subscription_termination_params_updated(None, None);

        let res = update_subscription_job_termination_params(&contracts_client, log);

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ServerlessError::NoSubscriptionJobFound(subscription_id)
        );
    }

    #[tokio::test]
    async fn test_update_subscription_job_termination_params_active_job() {
        let contracts_client = generate_contracts_client().await;
        let subscription_id = U256::from(1);
        let subscription_job = generate_generic_subscription_job(None, None);

        // Scope for write lock on subscription_jobs
        {
            let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
            subscription_jobs.insert(subscription_id, subscription_job.clone());
        }

        let new_termination_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 5000;
        let log =
            generate_job_subscription_termination_params_updated(None, Some(new_termination_time));

        let res = update_subscription_job_termination_params(&contracts_client, log);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ());

        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let result_subscription_job = subscription_jobs.get(&U256::from(1)).unwrap();

            assert_eq!(
                result_subscription_job.termination_time,
                new_termination_time
            );
        }
    }

    #[tokio::test]
    async fn test_process_historic_subscription_jobs_on_request_chain() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-2)).await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-3)).await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, Some(-4)).await;
        let request_chains_data = contracts_client.request_chains_data.read().unwrap().clone();
        let request_chain_data = request_chains_data.get(&CHAIN_ID).unwrap();
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);
        let (job_sub_tx, mut job_sub_rx) =
            tokio::sync::mpsc::channel::<JobSubscriptionChannelType>(100);
        let mock_http_provider = MockHttpProvider::new(None);

        process_historic_subscription_jobs_on_request_chain(
            &contracts_client,
            request_chain_data,
            req_chain_tx,
            job_sub_tx,
            mock_http_provider,
        )
        .await;

        // Sleep for 2s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(2)).await;

        if let Some(rx_job) = job_sub_rx.recv().await {
            if rx_job.subscription_action == JobSubscriptionAction::Add {
                assert_eq!(rx_job.subscription_id, U256::from(1));
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }

        if let Some(rx_job) = job_sub_rx.recv().await {
            if rx_job.subscription_action == JobSubscriptionAction::Add {
                assert_eq!(rx_job.subscription_id, U256::from(3));
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }

        let subscription_job_one: Option<SubscriptionJob>;
        // Scope for read lock on subscription_jobs
        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            subscription_job_one = subscription_jobs.get(&U256::from(1)).cloned();
        }

        assert!(subscription_job_one.is_some());

        let subscription_job_one = subscription_job_one.unwrap();
        assert_eq!(
            subscription_job_one.tx_hash,
            keccak256("9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e7d8"),
        );
        assert_eq!(
            subscription_job_one.code_input,
            Bytes::from(
                serde_json::to_vec(&json!({
                    "num": 108
                }))
                .unwrap(),
            )
        );

        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(subscription_job_one.termination_time >= system_time + 1490);
        assert!(subscription_job_one.termination_time <= system_time + 1510);

        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            let subscription_job_two = subscription_jobs.get(&U256::from(2));

            assert!(subscription_job_two.is_none());
        }

        assert!(job_sub_rx.recv().await.is_none());

        // Scope for read lock on subscription_job_instance_heap
        {
            let subscription_job_instance_heap_guard = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            let subscription_job_instance = subscription_job_instance_heap_guard.peek().unwrap();

            assert_eq!(subscription_job_instance.subscription_id, U256::from(1));
            assert_eq!(
                subscription_job_instance.next_trigger_time,
                subscription_job_one.starttime + subscription_job_one.interval
            );
        }

        let mut expected_job = subscription_job_to_relay_job(
            subscription_job_one.clone(),
            subscription_job_one.starttime,
        );
        expected_job.gateway_address = Some(contracts_client.enclave_address);
        expected_job.tx_hash = *CODE_HASH;
        expected_job.code_input = Bytes::from(
            serde_json::to_vec(&json!({
                "num": 10
            }))
            .unwrap(),
        );

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_some());
            assert_eq!(active_job.unwrap(), &expected_job);
        }
    }

    #[tokio::test]
    async fn test_trigger_subscription_job() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, None).await;
        let subscription_job = generate_generic_subscription_job(None, None);
        let trigger_timestamp = subscription_job.starttime;
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);

        trigger_subscription_job(
            subscription_job.clone(),
            trigger_timestamp,
            contracts_client.clone(),
            req_chain_tx,
        )
        .await;

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut expected_job =
            subscription_job_to_relay_job(subscription_job.clone(), subscription_job.starttime);
        expected_job.gateway_address = Some(contracts_client.enclave_address);

        // Scope for read lock on active_jobs
        {
            let active_jobs = contracts_client.active_jobs.read().unwrap();
            let active_job = active_jobs.get(&U256::from(1));

            assert!(active_job.is_some());
            assert_eq!(active_job.unwrap(), &expected_job);
        }
    }
}
