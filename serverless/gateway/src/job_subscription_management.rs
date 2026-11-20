use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Log,
    sol_types::{SolCall, SolEvent},
    transports::http::{reqwest::Url, Client, Http},
};
use log::{error, info};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{sleep_until, Instant},
};

use crate::{
    chain_util::{get_latest_block_number, retry_with_backoff, HttpProvider},
    constant::GATEWAY_BLOCK_STATES_TO_MAINTAIN,
    contract_abi::{
        IMulticall3,
        RelaySubscriptionsContract::{self, jobSubscriptionsCall, jobSubscriptionsReturn},
    },
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

// Ids of the subscriptions started on a RelaySubscriptions contract, from its jobSubsCount.
// jobSubsCount is | chain id (64 bits) | 1 (1 bit) | sub_id (64 bits) | 0 (127 bits) |, it starts
// with sub_id 0 and sub_id is incremented before each new subscription is stored, so the ids in
// use have sub_id 1 to the sub_id of jobSubsCount. After sub_id 2^64 - 1 the contract starts
// again from sub_id 1; the range then covers the ids written since, an older subscription with a
// higher sub_id would not be found. That needs 2^64 subscriptions.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionIdRange {
    prefix: U256,
    // last sub_id in use, 0 if there is none
    last_sub_id: u64,
}

impl SubscriptionIdRange {
    pub fn from_job_subs_count(job_subs_count: U256) -> Self {
        let prefix = (job_subs_count >> 191usize) << 191usize;
        let last_sub_id: U256 = (job_subs_count >> 127usize) & U256::from(u64::MAX);
        let last_sub_id = last_sub_id.to::<u64>();
        Self {
            prefix,
            last_sub_id,
        }
    }

    pub fn id(&self, sub_id: u64) -> U256 {
        self.prefix | (U256::from(sub_id) << 127usize)
    }

    pub fn len(&self) -> u64 {
        self.last_sub_id
    }

    // The ids in batches of at most batch_size ids, in order
    pub fn batches(&self, batch_size: u64) -> impl Iterator<Item = Vec<U256>> + '_ {
        let batch_size = batch_size.max(1);
        let mut next_sub_id = (self.last_sub_id >= 1).then_some(1u64);
        std::iter::from_fn(move || {
            let first = next_sub_id?;
            let last = std::cmp::min(first.saturating_add(batch_size - 1), self.last_sub_id);
            next_sub_id = (last < self.last_sub_id).then(|| last + 1);
            Some((first..=last).map(|sub_id| self.id(sub_id)).collect())
        })
    }
}

// Reads the state of a RelaySubscriptions contract
pub trait JobSubscriptionsReader {
    async fn job_subs_count(&self) -> Result<U256, ServerlessError>;
    // jobSubscriptions(id) for each of the ids, in the same order
    async fn job_subscriptions(
        &self,
        ids: &[U256],
    ) -> Result<Vec<jobSubscriptionsReturn>, ServerlessError>;
}

pub struct RelaySubscriptionsStateReader {
    provider: RootProvider<Http<Client>>,
    relay_subscriptions_address: Address,
    // None if Multicall3 is not deployed on the chain, the subscriptions are then read one by one
    multicall3_address: Option<Address>,
}

impl RelaySubscriptionsStateReader {
    pub async fn new(
        http_rpc_url: &str,
        relay_subscriptions_address: Address,
        multicall3_address: Address,
    ) -> Result<Self, ServerlessError> {
        let url = Url::parse(http_rpc_url)
            .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))?;
        let provider = ProviderBuilder::new().on_http(url);

        let code = retry_with_backoff(
            "get the code of the Multicall3 contract",
            ServerlessError::ContractCallFailure,
            || async {
                provider
                    .get_code_at(multicall3_address)
                    .await
                    .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))
            },
        )
        .await?;
        let multicall3_address = if code.is_empty() {
            info!(
                "Multicall3 is not deployed at {:?} on {}, the subscriptions are read one by one",
                multicall3_address, http_rpc_url
            );
            None
        } else {
            Some(multicall3_address)
        };

        Ok(Self {
            provider,
            relay_subscriptions_address,
            multicall3_address,
        })
    }
}

impl JobSubscriptionsReader for RelaySubscriptionsStateReader {
    async fn job_subs_count(&self) -> Result<U256, ServerlessError> {
        RelaySubscriptionsContract::new(self.relay_subscriptions_address, &self.provider)
            .jobSubsCount()
            .call()
            .await
            .map(|res| res._0)
            .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))
    }

    async fn job_subscriptions(
        &self,
        ids: &[U256],
    ) -> Result<Vec<jobSubscriptionsReturn>, ServerlessError> {
        let Some(multicall3_address) = self.multicall3_address else {
            let contract =
                RelaySubscriptionsContract::new(self.relay_subscriptions_address, &self.provider);
            let mut job_subscriptions = Vec::with_capacity(ids.len());
            for id in ids {
                let job_subscription = contract
                    .jobSubscriptions(*id)
                    .call()
                    .await
                    .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))?;
                job_subscriptions.push(job_subscription);
            }
            return Ok(job_subscriptions);
        };

        let calls = job_subscriptions_calls(self.relay_subscriptions_address, ids);
        let results = IMulticall3::new(multicall3_address, &self.provider)
            .aggregate3(calls)
            .call()
            .await
            .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))?
            .returnData;
        decode_job_subscriptions_results(&results)
    }
}

// Multicall3 calls of jobSubscriptions(id) for each of the ids
pub fn job_subscriptions_calls(
    relay_subscriptions_address: Address,
    ids: &[U256],
) -> Vec<IMulticall3::Call3> {
    ids.iter()
        .map(|id| IMulticall3::Call3 {
            target: relay_subscriptions_address,
            allowFailure: false,
            callData: jobSubscriptionsCall { _0: *id }.abi_encode().into(),
        })
        .collect()
}

pub fn decode_job_subscriptions_results(
    results: &[IMulticall3::Call3Result],
) -> Result<Vec<jobSubscriptionsReturn>, ServerlessError> {
    results
        .iter()
        .map(|result| {
            if !result.success {
                return Err(ServerlessError::ContractCallFailure(
                    "jobSubscriptions call failed in the multicall".to_owned(),
                ));
            }
            jobSubscriptionsCall::abi_decode_returns(&result.returnData, true)
                .map_err(|err| ServerlessError::ContractCallFailure(err.to_string()))
        })
        .collect()
}

// The subscription as JobSubscriptionStarted describes it, if it is active at the given time.
// The state reflects the later JobSubscriptionJobParamsUpdated and
// JobSubscriptionTerminationParamsUpdated events. A subscription that was refunded is deleted,
// its job owner is zero.
fn subscription_job_from_state(
    subscription_id: U256,
    request_chain_id: u64,
    job_subscription: &jobSubscriptionsReturn,
    current_timestamp: u64,
) -> Option<SubscriptionJob> {
    let job = &job_subscription.job;
    if job.jobOwner == Address::ZERO {
        return None;
    }

    let termination_time = job_subscription.terminationTimestamp.saturating_to::<u64>();
    if termination_time < current_timestamp {
        return None;
    }

    Some(SubscriptionJob {
        subscription_id,
        request_chain_id,
        subscriber: job.jobOwner,
        interval: job_subscription.periodicGap.saturating_to::<u64>(),
        termination_time,
        user_timeout: job_subscription.userTimeout,
        tx_hash: job.codehash,
        code_input: job.codeInputs.clone(),
        starttime: job.startTime.saturating_to::<u64>(),
        env: job.env,
    })
}

// Read the subscriptions that are active at the given time from the contract state, in batches
// of batch_size subscriptions. Each read is retried with a backoff.
pub async fn read_active_subscription_jobs<R: JobSubscriptionsReader>(
    reader: &R,
    request_chain_id: u64,
    batch_size: u64,
    current_timestamp: u64,
) -> Result<Vec<SubscriptionJob>, ServerlessError> {
    let job_subs_count = retry_with_backoff(
        "read jobSubsCount",
        ServerlessError::ContractCallFailure,
        || reader.job_subs_count(),
    )
    .await?;
    let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
    info!(
        "Reading {} subscriptions on request chain {}",
        ids.len(),
        request_chain_id
    );

    let mut subscription_jobs = Vec::new();
    for batch in ids.batches(batch_size) {
        let job_subscriptions = retry_with_backoff(
            "read jobSubscriptions",
            ServerlessError::ContractCallFailure,
            || reader.job_subscriptions(&batch),
        )
        .await?;
        if job_subscriptions.len() != batch.len() {
            return Err(ServerlessError::ContractCallFailure(format!(
                "{} subscriptions read for {} ids",
                job_subscriptions.len(),
                batch.len()
            )));
        }

        subscription_jobs.extend(batch.iter().zip(job_subscriptions.iter()).filter_map(
            |(id, job_subscription)| {
                subscription_job_from_state(
                    *id,
                    request_chain_id,
                    job_subscription,
                    current_timestamp,
                )
            },
        ));
    }

    Ok(subscription_jobs)
}

// Add the active subscriptions read from the contract state as the JobSubscriptionStarted event
// would. A gateway serves subscriptions started before it, which can run for years, so they are
// not read from the logs.
pub async fn add_subscription_jobs_from_state<R: JobSubscriptionsReader>(
    contracts_client: &Arc<ContractsClient>,
    reader: &R,
    request_chain_id: u64,
    req_chain_tx: Sender<Job>,
    job_sub_tx: Sender<JobSubscriptionChannelType>,
) -> Result<(), ServerlessError> {
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let subscription_jobs = read_active_subscription_jobs(
        reader,
        request_chain_id,
        contracts_client.subscriptions_batch_size,
        current_timestamp,
    )
    .await?;
    info!(
        "Loaded {} active subscriptions on request chain {}",
        subscription_jobs.len(),
        request_chain_id
    );

    for subscription_job in subscription_jobs {
        let Ok(sub_id) = insert_subscription_job(
            contracts_client,
            subscription_job,
            req_chain_tx.clone(),
            true,
        ) else {
            continue;
        };
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
    }

    Ok(())
}

// Load the active subscriptions of a request chain from the RelaySubscriptions contract state.
// Returns the latest block before the state was read, the event stream of the request chain
// continues from the next block. Events of the blocks after it can be part of the state read
// already; handling them again gives the same result, a started subscription is added once and
// the updates are applied in order.
pub async fn load_active_subscription_jobs(
    contracts_client: &Arc<ContractsClient>,
    request_chain_data: &RequestChainData,
    req_chain_tx: Sender<Job>,
    job_sub_tx: Sender<JobSubscriptionChannelType>,
) -> Result<u64, ServerlessError> {
    let http_provider = HttpProvider::new(request_chain_data.http_rpc_url.clone());
    let block_number = get_latest_block_number(&http_provider).await?;

    let reader = RelaySubscriptionsStateReader::new(
        &request_chain_data.http_rpc_url,
        request_chain_data.relay_subscriptions_address,
        contracts_client.multicall3_address,
    )
    .await?;

    add_subscription_jobs_from_state(
        contracts_client,
        &reader,
        request_chain_data.chain_id,
        req_chain_tx,
        job_sub_tx,
    )
    .await?;

    Ok(block_number)
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
                    continue;
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

    insert_subscription_job(
        contracts_client,
        subscription_job,
        req_chain_tx,
        is_historic_log,
    )
}

// Add the subscription and schedule its instances. is_historic_log is set for a subscription
// that started before the gateway learnt about it.
fn insert_subscription_job(
    contracts_client: &Arc<ContractsClient>,
    subscription_job: SubscriptionJob,
    req_chain_tx: Sender<Job>,
    is_historic_log: bool,
) -> Result<U256, ServerlessError> {
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
        // The same log can come from both the historic logs and the events stream
        if subscription_jobs.contains_key(&subscription_job.subscription_id) {
            info!(
                "Subscription Job is already added - Subscription ID: {}",
                subscription_job.subscription_id
            );
            return Ok(U256::from(0));
        }
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
        primitives::{keccak256, Bytes, Log as InnerLog, LogData},
        signers::local::PrivateKeySigner,
    };
    use serde_json::json;
    use std::{collections::HashMap, sync::Mutex};

    use crate::constant::{
        REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT,
        REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT,
        REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT,
    };

    use super::*;

    use crate::test_util::{
        add_gateway_epoch_state, generate_contracts_client, generate_generic_subscription_job,
        generate_job_subscription_job_params_updated, generate_job_subscription_started_log,
        generate_job_subscription_termination_params_updated, CHAIN_ID, CODE_HASH,
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
    async fn test_add_subscription_job_already_added() {
        let contracts_client = generate_contracts_client().await;
        add_gateway_epoch_state(contracts_client.clone(), None, None, None).await;
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);

        let res = add_subscription_job(
            &contracts_client,
            generate_job_subscription_started_log(None, None),
            CHAIN_ID,
            req_chain_tx.clone(),
            false,
        );
        assert_eq!(res.unwrap(), U256::from(1));

        // Same log received again
        let res = add_subscription_job(
            &contracts_client,
            generate_job_subscription_started_log(None, None),
            CHAIN_ID,
            req_chain_tx,
            false,
        );
        assert_eq!(res.unwrap(), U256::from(0));

        // Sleep for 1s to allow all async tasks to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(contracts_client.subscription_jobs.read().unwrap().len(), 1);
        assert_eq!(
            contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_job_subscription_manager_stale_heap_entry() {
        let contracts_client = generate_contracts_client().await;
        let (req_chain_tx, _com_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);
        let (_job_sub_tx, job_sub_rx) =
            tokio::sync::mpsc::channel::<JobSubscriptionChannelType>(100);

        // Heap entry of a subscription that is no longer present
        contracts_client
            .subscription_job_instance_heap
            .write()
            .unwrap()
            .push(SubscriptionJobInstanceHeap {
                subscription_id: U256::from(1),
                next_trigger_time: 0,
            });

        let manager = tokio::spawn(job_subscription_manager(
            contracts_client.clone(),
            job_sub_rx,
            req_chain_tx,
        ));

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(contracts_client
            .subscription_job_instance_heap
            .read()
            .unwrap()
            .is_empty());
        assert!(!manager.is_finished());
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

    // jobSubsCount after initialize, as RelaySubscriptions sets it
    fn initial_job_subs_count(chain_id: u64) -> U256 {
        (U256::from(chain_id) << 192usize) | (U256::from(1) << 191usize)
    }

    // RelaySubscriptions._updateJobSubsCount, called before each new subscription is stored
    fn update_job_subs_count(job_subs_count: U256, chain_id: u64) -> U256 {
        let sub_id: U256 = (job_subs_count >> 127usize) & U256::from(u64::MAX);
        let mut job_subs_count = job_subs_count;
        if sub_id == U256::from(u64::MAX) {
            job_subs_count = initial_job_subs_count(chain_id);
        }
        job_subs_count + (U256::from(1) << 127usize)
    }

    #[test]
    fn test_subscription_id_range() {
        // no subscription yet
        let job_subs_count = initial_job_subs_count(CHAIN_ID);
        let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
        assert_eq!(ids.len(), 0);
        assert_eq!(ids.batches(500).count(), 0);

        // the ids the contract stores the subscriptions at
        let mut job_subs_count = job_subs_count;
        let mut stored_ids = Vec::new();
        for _ in 0..5 {
            job_subs_count = update_job_subs_count(job_subs_count, CHAIN_ID);
            stored_ids.push(job_subs_count);
        }

        let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
        assert_eq!(ids.len(), 5);
        assert_eq!(
            ids.id(1),
            initial_job_subs_count(CHAIN_ID) | (U256::from(1) << 127usize)
        );
        let batches: Vec<Vec<U256>> = ids.batches(2).collect();
        assert_eq!(
            batches,
            vec![
                stored_ids[0..2].to_vec(),
                stored_ids[2..4].to_vec(),
                stored_ids[4..5].to_vec()
            ]
        );
        assert_eq!(ids.batches(5).collect::<Vec<_>>(), vec![stored_ids.clone()]);
        assert_eq!(
            ids.batches(500).collect::<Vec<_>>(),
            vec![stored_ids.clone()]
        );
        // a batch size of 0 reads one subscription per call
        assert_eq!(ids.batches(0).count(), 5);
    }

    #[test]
    fn test_subscription_id_range_wrap_around() {
        // the last two sub ids before the contract starts again from sub_id 1
        let job_subs_count =
            initial_job_subs_count(CHAIN_ID) | (U256::from(u64::MAX - 2) << 127usize);
        let job_subs_count = update_job_subs_count(job_subs_count, CHAIN_ID);
        let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
        assert_eq!(ids.len(), u64::MAX - 1);
        assert_eq!(ids.batches(3).next().unwrap().len(), 3);

        let job_subs_count = update_job_subs_count(job_subs_count, CHAIN_ID);
        let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
        assert_eq!(ids.len(), u64::MAX);
        assert_eq!(ids.id(u64::MAX), job_subs_count);

        // wrapped around, the next subscription is stored at sub_id 1
        let job_subs_count = update_job_subs_count(job_subs_count, CHAIN_ID);
        let ids = SubscriptionIdRange::from_job_subs_count(job_subs_count);
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids.batches(500).collect::<Vec<_>>(),
            vec![vec![job_subs_count]]
        );
        // the chain id prefix is kept
        assert_eq!(
            ids.id(1) >> 191usize,
            initial_job_subs_count(CHAIN_ID) >> 191usize
        );
    }

    // ABI encoded return data of jobSubscriptions(id)
    fn encode_job_subscription(
        job_owner: Address,
        start_time: u64,
        periodic_gap: u64,
        termination_timestamp: u64,
        code_inputs: &[u8],
    ) -> Bytes {
        DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(periodic_gap), 256),
            DynSolValue::Uint(U256::from(termination_timestamp), 256),
            DynSolValue::Uint(U256::from(3), 256),
            DynSolValue::Uint(U256::from(start_time + periodic_gap), 256),
            DynSolValue::Uint(U256::from(2000), 256),
            DynSolValue::Address(job_owner),
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(U256::from(start_time), 256),
                DynSolValue::Uint(U256::from(1000), 256),
                DynSolValue::Uint(U256::from(500000), 256),
                DynSolValue::Uint(U256::from(10000), 256),
                DynSolValue::Uint(U256::from(100000), 256),
                DynSolValue::Address(job_owner),
                DynSolValue::Address(Address::ZERO),
                DynSolValue::Uint(U256::from(1), 8),
                DynSolValue::FixedBytes(*CODE_HASH, 32),
                DynSolValue::Bytes(code_inputs.to_vec()),
            ]),
        ])
        .abi_encode_params()
        .into()
    }

    #[test]
    fn test_job_subscriptions_multicall_encoding() {
        let relay_subscriptions_address = PrivateKeySigner::random().address();
        let ids = vec![U256::from(1), U256::from(2)];

        let calls = job_subscriptions_calls(relay_subscriptions_address, &ids);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].target, relay_subscriptions_address);
        assert!(!calls[1].allowFailure);
        let mut expected_call_data = keccak256("jobSubscriptions(uint256)")[..4].to_vec();
        expected_call_data.extend_from_slice(&U256::from(2).to_be_bytes::<32>());
        assert_eq!(calls[1].callData.to_vec(), expected_call_data);
        assert_eq!(
            IMulticall3::aggregate3Call::SELECTOR,
            keccak256("aggregate3((address,bool,bytes)[])")[..4]
        );

        let owner = PrivateKeySigner::random().address();
        let results = vec![
            IMulticall3::Call3Result {
                success: true,
                returnData: encode_job_subscription(owner, 100, 10, 1000, b"input"),
            },
            IMulticall3::Call3Result {
                success: true,
                returnData: encode_job_subscription(Address::ZERO, 0, 0, 0, b""),
            },
        ];
        let decoded = decode_job_subscriptions_results(&results).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].periodicGap, U256::from(10));
        assert_eq!(decoded[0].terminationTimestamp, U256::from(1000));
        assert_eq!(decoded[0].userTimeout, U256::from(2000));
        assert_eq!(decoded[0].job.jobOwner, owner);
        assert_eq!(decoded[0].job.startTime, U256::from(100));
        assert_eq!(decoded[0].job.env, 1);
        assert_eq!(decoded[0].job.codehash, *CODE_HASH);
        assert_eq!(decoded[0].job.codeInputs, Bytes::from_static(b"input"));
        assert_eq!(decoded[1].job.jobOwner, Address::ZERO);

        let failed = vec![IMulticall3::Call3Result {
            success: false,
            returnData: Bytes::new(),
        }];
        assert!(decode_job_subscriptions_results(&failed).is_err());
    }

    // Reader of a contract state given as the return data of jobSubscriptions by sub_id
    struct MockJobSubscriptionsReader {
        job_subs_count: U256,
        job_subscriptions: HashMap<U256, Bytes>,
        batch_sizes: Mutex<Vec<usize>>,
        failing_calls: Mutex<usize>,
    }

    impl JobSubscriptionsReader for MockJobSubscriptionsReader {
        async fn job_subs_count(&self) -> Result<U256, ServerlessError> {
            Ok(self.job_subs_count)
        }

        async fn job_subscriptions(
            &self,
            ids: &[U256],
        ) -> Result<Vec<jobSubscriptionsReturn>, ServerlessError> {
            {
                let mut failing_calls = self.failing_calls.lock().unwrap();
                if *failing_calls > 0 {
                    *failing_calls -= 1;
                    return Err(ServerlessError::ContractCallFailure(
                        "mock failure".to_owned(),
                    ));
                }
            }
            self.batch_sizes.lock().unwrap().push(ids.len());
            Ok(ids
                .iter()
                .map(|id| {
                    let data =
                        self.job_subscriptions.get(id).cloned().unwrap_or_else(|| {
                            encode_job_subscription(Address::ZERO, 0, 0, 0, b"")
                        });
                    jobSubscriptionsCall::abi_decode_returns(&data, true).unwrap()
                })
                .collect())
        }
    }

    // 5 subscriptions: 1, 3 and 5 active, 2 deleted after its refund, 4 terminated
    fn mock_reader(now: u64, owner: Address) -> MockJobSubscriptionsReader {
        let mut job_subs_count = initial_job_subs_count(CHAIN_ID);
        let mut job_subscriptions = HashMap::new();
        for sub_id in 1..=5u64 {
            job_subs_count = update_job_subs_count(job_subs_count, CHAIN_ID);
            let data = match sub_id {
                2 => encode_job_subscription(Address::ZERO, 0, 0, 0, b""),
                4 => encode_job_subscription(owner, now - 1000, 10, now - 1, b"old"),
                _ => encode_job_subscription(owner, now - 100_000, 20, now + 1500, b"input"),
            };
            job_subscriptions.insert(job_subs_count, data);
        }
        MockJobSubscriptionsReader {
            job_subs_count,
            job_subscriptions,
            batch_sizes: Mutex::new(Vec::new()),
            failing_calls: Mutex::new(0),
        }
    }

    #[tokio::test]
    async fn test_read_active_subscription_jobs() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = PrivateKeySigner::random().address();
        let reader = mock_reader(now, owner);
        // the first read of a batch fails and is retried
        *reader.failing_calls.lock().unwrap() = 1;

        let jobs = read_active_subscription_jobs(&reader, CHAIN_ID, 2, now)
            .await
            .unwrap();

        assert_eq!(*reader.batch_sizes.lock().unwrap(), vec![2, 2, 1]);
        let ids = SubscriptionIdRange::from_job_subs_count(reader.job_subs_count);
        assert_eq!(
            jobs.iter()
                .map(|job| job.subscription_id)
                .collect::<Vec<_>>(),
            vec![ids.id(1), ids.id(3), ids.id(5)]
        );
        assert_eq!(
            jobs[0],
            SubscriptionJob {
                subscription_id: ids.id(1),
                request_chain_id: CHAIN_ID,
                subscriber: owner,
                interval: 20,
                termination_time: now + 1500,
                user_timeout: U256::from(2000),
                tx_hash: *CODE_HASH,
                code_input: Bytes::from_static(b"input"),
                starttime: now - 100_000,
                env: 1,
            }
        );
    }

    #[tokio::test]
    async fn test_read_active_subscription_jobs_returns_the_error() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reader = mock_reader(now, PrivateKeySigner::random().address());
        *reader.failing_calls.lock().unwrap() = usize::MAX;

        let res = read_active_subscription_jobs(&reader, CHAIN_ID, 500, now).await;

        assert_eq!(
            res,
            Err(ServerlessError::ContractCallFailure(
                "mock failure".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn test_add_subscription_jobs_from_state() {
        let contracts_client = generate_contracts_client().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = PrivateKeySigner::random().address();
        let reader = mock_reader(now, owner);
        let ids = SubscriptionIdRange::from_job_subs_count(reader.job_subs_count);
        let (req_chain_tx, _req_chain_rx) = tokio::sync::mpsc::channel::<Job>(100);
        let (job_sub_tx, mut job_sub_rx) =
            tokio::sync::mpsc::channel::<JobSubscriptionChannelType>(100);

        add_subscription_jobs_from_state(
            &contracts_client,
            &reader,
            CHAIN_ID,
            req_chain_tx.clone(),
            job_sub_tx.clone(),
        )
        .await
        .unwrap();

        for sub_id in [1, 3, 5] {
            let rx_job = job_sub_rx.recv().await.unwrap();
            assert_eq!(rx_job.subscription_action, JobSubscriptionAction::Add);
            assert_eq!(rx_job.subscription_id, ids.id(sub_id));
        }
        assert!(job_sub_rx.try_recv().is_err());

        {
            let subscription_jobs = contracts_client.subscription_jobs.read().unwrap();
            assert_eq!(subscription_jobs.len(), 3);
            assert!(subscription_jobs.contains_key(&ids.id(1)));
            assert!(!subscription_jobs.contains_key(&ids.id(2)));
            assert!(!subscription_jobs.contains_key(&ids.id(4)));
        }

        // the instances are scheduled from the maintained block states on, not from the start
        {
            let minimum_timestamp_for_job = get_minimum_timestamp_for_job(&contracts_client);
            let heap = contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap();
            assert_eq!(heap.len(), 3);
            for instance in heap.iter() {
                assert!(instance.next_trigger_time >= minimum_timestamp_for_job);
                assert!(instance.next_trigger_time < minimum_timestamp_for_job + 20 + 1);
            }
        }

        // loading again, as after a replay of the events, does not add them twice
        add_subscription_jobs_from_state(
            &contracts_client,
            &reader,
            CHAIN_ID,
            req_chain_tx,
            job_sub_tx,
        )
        .await
        .unwrap();
        assert!(job_sub_rx.try_recv().is_err());
        assert_eq!(contracts_client.subscription_jobs.read().unwrap().len(), 3);
        assert_eq!(
            contracts_client
                .subscription_job_instance_heap
                .read()
                .unwrap()
                .len(),
            3
        );
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
