use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use alloy_primitives::U256;
use anyhow::{anyhow, Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool, Type};
use tokio::sync::mpsc::{self, Sender};
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tracing::{error, info, info_span, Instrument};

// IMPORTANT: do not import SystemTime, use a SystemContext

// Trait to encapsulate behavior that should be simulated in tests
trait SystemContext {
    fn now_timestamp(&self) -> Duration;
}

struct RealSystemContext {}

impl SystemContext for RealSystemContext {
    fn now_timestamp(&self) -> Duration {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
    }
}

// Basic architecture:
// One future listening to new jobs
// Each job has its own future managing its lifetime

// Identify jobs not only by the id, but also by the operator, contract and the chain
// This is needed to cleanly support multiple operators/contracts/chains at the infra level
#[derive(Clone)]
pub struct JobId {
    pub id: String,
    pub operator: String,
    pub contract: String,
    pub chain: String,
}

pub trait InfraProvider {
    fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    fn spin_down(&mut self, job: &JobId, region: &str, bandwidth: u64) -> impl Future<Output = Result<()>> + Send;

    fn get_job_ip(&self, job: &JobId, region: &str) -> impl Future<Output = Result<String>> + Send;

    fn check_enclave_running(
        &mut self,
        job: &JobId,
        region: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl<T> InfraProvider for &mut T
where
    T: InfraProvider + Send + Sync,
{
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> Result<()> {
        (**self)
            .spin_up(
                job,
                instance_type,
                region,
                req_mem,
                req_vcpu,
                bandwidth,
                image_url,
                init_params,
            )
            .await
    }

    async fn spin_down(&mut self, job: &JobId, region: &str, bandwidth: u64) -> Result<()> {
        (**self).spin_down(job, region, bandwidth).await
    }

    async fn get_job_ip(&self, job: &JobId, region: &str) -> Result<String> {
        (**self).get_job_ip(job, region).await
    }

    async fn check_enclave_running(&mut self, job: &JobId, region: &str) -> Result<bool> {
        (**self).check_enclave_running(job, region).await
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RateCard {
    pub instance: String,
    pub min_rate: U256,
    pub cpu: u32,
    pub memory: u32,
    pub arch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RegionalRates {
    pub region: String,
    pub rate_cards: Vec<RateCard>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GBRateCard {
    pub region: String,
    pub region_code: String,
    pub rate: U256,
}

#[derive(Clone, Debug, Type)]
#[sqlx(type_name = "event_name", rename_all = "PascalCase")]
pub enum JobEventName {
    Opened,
    Closed,
    Deposited,
    Settled,
    MetadataUpdated,
    Withdrew,
    ReviseRateInitiated,
    ReviseRateCancelled,
    ReviseRateFinalized,
}

#[derive(Debug, FromRow)]
pub struct JobEvent {
    pub id: i64,
    pub job_id: String,
    pub event_name: JobEventName,
    pub event_data: Value,
}

#[derive(Debug, Deserialize)]
pub struct JobOpened {
    pub job_id: String,
    pub owner: String,
    pub provider: String,
    pub metadata: String,
    pub rate: U256,
    pub balance: U256,
    pub timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct JobClosed {
    pub job_id: String,
}

#[derive(Debug, Deserialize)]
pub struct JobDeposited {
    pub job_id: String,
    pub from: String,
    pub amount: U256,
}

#[derive(Debug, Deserialize)]
pub struct JobSettled {
    pub job_id: String,
    pub amount: U256,
    pub timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct JobMetadataUpdated {
    pub job_id: String,
    pub new_metadata: String,
}

#[derive(Debug, Deserialize)]
pub struct JobWithdrew {
    pub job_id: String,
    pub to: String,
    pub amount: U256,
}

#[derive(Debug, Deserialize)]
pub struct JobReviseRateInitiated {
    pub job_id: String,
    pub new_rate: U256,
}

#[derive(Debug, Deserialize)]
pub struct JobReviseRateCancelled {
    pub job_id: String,
}

#[derive(Debug, Deserialize)]
pub struct JobReviseRateFinalized {
    pub job_id: String,
    pub new_rate: U256,
}

#[derive(Debug)]
pub enum DecodedJobEvent {
    Opened(JobOpened),
    Closed(JobClosed),
    Deposited(JobDeposited),
    Withdrew(JobWithdrew),
    Settled(JobSettled),
    ReviseRateInitiated(JobReviseRateInitiated),
    ReviseRateCancelled(JobReviseRateCancelled),
    ReviseRateFinalized(JobReviseRateFinalized),
    MetadataUpdated(JobMetadataUpdated),
}

#[derive(PartialEq, Debug)]
enum JobResult {
    // success
    Success,
    // done, should still terminate instance, if any
    Done,
    // error, should terminate instance, if any
    Failed,
    // error, likely internal bug, exit but do not terminate instance
    Internal,
}

pub async fn run(
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    db_url: String,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    extra_decimals: i64,
    // without job_id.id set
    job_id: JobId,
    job_registry: JobRegistry,
) {
    let mut backoff = 1;

    // connection level loop
    // start from scratch in case of connection errors
    // trying to implicitly resume connections can cause issues

    let mut last_processed_id: i64 = -1;
    loop {
        info!("Connecting to DB endpoint...");
        let db_pool = match PgPoolOptions::new()
            .connect(&db_url)
            .await
            .context("failed to connect to the provided db url")
        {
            Ok(pool) => pool,
            Err(err) => {
                error!(?err, "DB connection error");
                // exponential backoff on connection errors
                sleep(Duration::from_secs(backoff)).await;
                backoff *= 2;
                if backoff > 128 {
                    backoff = 128;
                }
                continue;
            }
        };
        info!("Connected to DB endpoint");

        'run: loop {
            sleep(Duration::from_secs(5)).await;

            let mut attempts = 5;
            let mut delay = 100;

            let job_events;

            loop {
                match fetch_job_events(&db_pool, last_processed_id).await {
                    Ok(events) => {
                        job_events = events;
                        break;
                    }
                    Err(err) => {
                        error!(?err, "DB fetch error");

                        if attempts == 0 {
                            break 'run;
                        }

                        sleep(Duration::from_millis(delay)).await;
                        delay *= 2;
                        attempts -= 1;
                    }
                }
            }

            for event in job_events {
                let sender = match event.event_name {
                    JobEventName::Opened => {
                        info!(?event.job_id, "New job");

                        // prepare with correct job id
                        let mut job_id = job_id.clone();
                        job_id.id = event.job_id.clone();

                        // Skip if this job has already been terminated
                        if job_registry.is_job_terminated(&job_id.id) {
                            info!("Skipping already terminated job: {}", job_id.id);
                            last_processed_id = event.id;
                            continue;
                        }

                        if job_registry
                            .active_jobs
                            .lock()
                            .unwrap()
                            .contains_key(&job_id.id)
                        {
                            info!("Skipping already running job: {}", job_id.id);
                            last_processed_id = event.id;
                            continue;
                        }

                        let (tx, rx) = mpsc::channel::<JobEvent>(100);
                        job_registry
                            .active_jobs
                            .lock()
                            .unwrap()
                            .insert(job_id.id.clone(), tx.clone());

                        tokio::spawn(
                            job_manager(
                                RealSystemContext {},
                                rx,
                                infra_provider.clone(),
                                job_id,
                                regions,
                                3,
                                rates,
                                gb_rates,
                                address_whitelist,
                                address_blacklist,
                                extra_decimals,
                                job_registry.clone(),
                            )
                            .instrument(info_span!(parent: None, "job", ?event.job_id)),
                        );

                        Some(tx)
                    }
                    _ => {
                        let guard = job_registry.active_jobs.lock().unwrap();
                        guard.get(&event.job_id).cloned()
                    }
                };

                let event_id = event.id;

                if let Some(sender) = sender {
                    if let Err(err) = sender.send(event).await {
                        // should not happen in reality
                        // TODO: add handling (likely random panic in the job manager)
                        error!(?err, "Channel sender error");
                        break 'run;
                    }
                }

                last_processed_id = event_id;
            }
        }
    }
}

async fn fetch_job_events(
    pool: &PgPool,
    last_processed_id: i64,
) -> Result<Vec<JobEvent>, sqlx::Error> {
    let events = sqlx::query_as::<_, JobEvent>(
        r#"
        SELECT id, job_id, event_name, event_data
        FROM job_events
        WHERE id > $1
        ORDER BY id ASC
        LIMIT 1000
        "#,
    )
    .bind(last_processed_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

// manage the complete lifecycle of a job
async fn job_manager(
    context: impl SystemContext + Send + Sync,
    mut events_stream: mpsc::Receiver<JobEvent>,
    mut infra_provider: impl InfraProvider + Send + Sync,
    job_id: JobId,
    allowed_regions: &[String],
    aws_delay_duration: u64,
    rates: &[RegionalRates],
    gb_rates: &[GBRateCard],
    address_whitelist: &[String],
    address_blacklist: &[String],
    extra_decimals: i64,
    job_registry: JobRegistry,
) -> JobResult {
    let mut state = JobState::new(
        &context,
        job_id.clone(),
        aws_delay_duration,
        allowed_regions,
    );

    // usually tracks the result of the last log processed
    let mut job_result = JobResult::Success;

    let mut cur_id: i64 = -1;

    // The processing loop follows this:
    // Keep processing events till you hit an unsuccessful processing
    // If result is Retry or Internal, these are likely RPC issues and bugs
    // Hence just break out, the parent function handles retrying
    // If result is Done, the job is naturally "done", schedule termination
    // If result is Failed, the job ran into a user error, schedule termination
    // If job is insolvent, schedule termination
    // Once job is successfully terminated, break out
    // Insolvency and heartbeats only matter when job is not already scheduled for termination
    'event: loop {
        // compute time to insolvency
        let insolvency_duration = state.insolvency_duration(extra_decimals);
        info!(duration = insolvency_duration.as_secs(), "Insolvency after");

        let aws_delay_timeout = state
            .infra_change_time
            .saturating_duration_since(Instant::now());

        // NOTE: some stuff like cargo fmt does not work inside this macro
        // extract as much stuff as possible outside it
        tokio::select! {
            // order matters
            // first process all logs because they might end up closing the job
            // then process insolvency because it might end up closing the job
            // then infra changes
            // then heartbeat
            // this ensures that any log which results in a job getting closed or insolvent
            // is given priority and the job is terminated even if other infra changes are
            // scheduled
            biased;

            // keep processing logs till the processing is successful
            log = events_stream.recv(), if job_result == JobResult::Success => {
                job_result = match log {
                    Some(log) => {
                        if log.id <= cur_id {
                            return JobResult::Success;
                        }

                        cur_id = log.id;

                        match parse_event(log.event_name, log.event_data) {
                            Ok(event) => state.process_event(event, rates, gb_rates, address_whitelist, address_blacklist),
                            Err(result) => result
                        }
                    }
                    None => JobResult::Internal,
                };

                match job_result {
                    // just proceed
                    JobResult::Success => {},
                    // terminate
                    JobResult::Done => {
                        state.schedule_termination(0);
                    },
                    // terminate
                    JobResult::Failed => {
                        state.schedule_termination(0);
                    },
                    // break
                    JobResult::Internal => break 'event,
                };
            }

            // insolvency check
            // enable when processing is successful
            () = sleep(insolvency_duration), if job_result == JobResult::Success => {
                state.handle_insolvency();
                job_result = JobResult::Done;
            }

            // aws delayed spin up check
            // should only happen if scheduled
            () = sleep(aws_delay_timeout), if state.infra_change_scheduled => {
                let res = state.change_infra(&mut infra_provider).await;
                if res && !state.infra_state {
                    // successful termination, exit
                    break 'event;
                }
            }

            // running instance heartbeat check
            // should only happen if infra change is not scheduled
            () = sleep(Duration::from_secs(5)), if !state.infra_change_scheduled => {
                state.heartbeat_check(&mut infra_provider).await;
            }
        }
    }

    if job_result == JobResult::Done || job_result == JobResult::Failed {
        job_registry.add_terminated_job(job_id.id.clone());
    }

    job_registry.remove_active_job(job_id.id);

    job_result
}

fn parse_event(event_name: JobEventName, event_data: Value) -> Result<DecodedJobEvent, JobResult> {
    match event_name {
        JobEventName::Opened => Ok(DecodedJobEvent::Opened(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "OPENED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::Closed => Ok(DecodedJobEvent::Closed(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "CLOSED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::Deposited => Ok(DecodedJobEvent::Deposited(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "DEPOSITED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::Settled => Ok(DecodedJobEvent::Settled(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "SETTLED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::MetadataUpdated => Ok(DecodedJobEvent::MetadataUpdated(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "METADATA_UPDATED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::Withdrew => Ok(DecodedJobEvent::Withdrew(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "WITHDREW: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::ReviseRateInitiated => Ok(DecodedJobEvent::ReviseRateInitiated(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "JOB_REVISE_RATE_INITIATED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::ReviseRateCancelled => Ok(DecodedJobEvent::ReviseRateCancelled(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "JOB_REVISE_RATE_CANCELLED: Decode failure")).map_err(|_| JobResult::Internal)?)),
        JobEventName::ReviseRateFinalized => Ok(DecodedJobEvent::ReviseRateFinalized(serde_json::from_value(event_data.clone()).inspect_err(|err| error!(?err, data = ?event_data, "JOB_REVISE_RATE_FINALIZED: Decode failure")).map_err(|_| JobResult::Internal)?)),
    }
}

fn whitelist_blacklist_check(
    owner: String,
    address_whitelist: &[String],
    address_blacklist: &[String],
) -> bool {
    // check whitelist
    if !address_whitelist.is_empty() {
        info!("Checking address whitelist...");
        if address_whitelist.iter().any(|s| s == &owner) {
            info!("ADDRESS ALLOWED!");
        } else {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        }
    }

    // check blacklist
    if !address_blacklist.is_empty() {
        info!("Checking address blacklist...");
        if address_blacklist.iter().any(|s| s == &owner) {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        } else {
            info!("ADDRESS ALLOWED!");
        }
    }

    true
}

struct JobState<'a> {
    // NOTE: not sure if dyn is a good idea, revisit later
    context: &'a (dyn SystemContext + Send + Sync),

    job_id: JobId,
    launch_delay: u64,
    allowed_regions: &'a [String],

    balance: U256,
    last_settled: Duration,
    rate: U256,
    original_rate: U256,
    min_rate: U256,
    bandwidth: u64,
    eif_url: String, // [Update Note] TODO: Change name of eif
    instance_type: String,
    region: String,
    req_vcpus: i32,
    req_mem: i64,
    init_params: Box<[u8]>,

    // whether instance should exist or not
    infra_state: bool,
    // how long to wait for infra change
    infra_change_time: Instant,
    // whether to schedule change
    infra_change_scheduled: bool,
}

impl<'a> JobState<'a> {
    fn new(
        context: &'a (dyn SystemContext + Send + Sync),
        job_id: JobId,
        launch_delay: u64,
        allowed_regions: &'a [String],
    ) -> JobState<'a> {
        // solvency metrics
        // default of 60s
        JobState {
            context,
            job_id,
            launch_delay,
            allowed_regions,
            balance: U256::from(360),
            last_settled: context.now_timestamp(),
            rate: U256::from(1),
            original_rate: U256::from(1),
            min_rate: U256::MAX,
            bandwidth: 0,
            eif_url: String::new(),
            instance_type: "c6a.xlarge".to_string(),
            region: "ap-south-1".to_string(),
            req_vcpus: 2,
            req_mem: 4096,
            init_params: Box::new([0; 0]),
            infra_state: false,
            infra_change_time: Instant::now(),
            infra_change_scheduled: false,
        }
    }

    fn insolvency_duration(&self, extra_decimals: i64) -> Duration {
        let now_ts = self.context.now_timestamp();

        if self.rate == U256::ZERO {
            Duration::from_secs(0)
        } else {
            // solvent for balance / rate seconds from last_settled with 300s as margin
            Duration::from_secs(
                (self.balance * U256::from(10).pow(U256::from(extra_decimals)) / self.rate)
                    .saturating_to::<u64>()
                    .saturating_sub(300),
            )
            .saturating_sub(now_ts.saturating_sub(self.last_settled))
        }
    }

    async fn heartbeat_check(&mut self, mut infra_provider: impl InfraProvider) {
        let Ok(is_enclave_running) = infra_provider
            .check_enclave_running(&self.job_id, &self.region)
            .await
            .inspect_err(|err| error!(?err, "Failed to retrieve enclave state"))
        else {
            return;
        };

        if is_enclave_running {
            return;
        }

        info!("Enclave not running, scheduling new launch");
        self.schedule_launch(0);
    }

    fn handle_insolvency(&mut self) {
        info!("INSOLVENCY");
        self.schedule_termination(0);
    }

    fn schedule_launch(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = true;
        info!("Instance launch scheduled");
    }

    fn schedule_termination(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = false;
        info!("Instance termination scheduled");
    }

    // exists to implement rescheduling of infra changes on errors
    async fn change_infra(&mut self, infra_provider: impl InfraProvider) -> bool {
        let res = self.change_infra_impl(infra_provider).await;
        if res {
            // successful
            self.infra_change_scheduled = false;
        } else {
            // failed, reschedule with small delay
            self.infra_change_time = Instant::now() + Duration::from_secs(2);
        }

        res
    }

    // on errors, return false, will be rescheduled after a short delay
    async fn change_infra_impl(&mut self, mut infra_provider: impl InfraProvider) -> bool {
        if self.infra_state {
            // launch mode
            let res = infra_provider
                .spin_up(
                    &self.job_id,
                    self.instance_type.as_str(),
                    &self.region,
                    self.req_mem,
                    self.req_vcpus,
                    self.bandwidth,
                    &self.eif_url,
                    &self.init_params,
                )
                .await;
            if let Err(err) = res {
                error!(?err, "Instance launch failed");
                return false;
            }

            true
        } else {
            // terminate mode
            let res = infra_provider.spin_down(&self.job_id, &self.region, self.bandwidth).await;
            if let Err(err) = res {
                error!(?err, "Failed to terminate instance");
                return false;
            }

            true
        }
    }

    // return
    // JobResult::Success on successful processing of a log
    // JobResult::Done on successful processing of a log which ends a job
    // JobResult::Failed on unrecoverable errors
    // JobResult::Internal on internal errors, usually bugs
    pub fn process_event(
        &mut self,
        event: DecodedJobEvent,
        rates: &[RegionalRates],
        gb_rates: &[GBRateCard],
        address_whitelist: &[String],
        address_blacklist: &[String],
    ) -> JobResult {
        info!(event = ?event, "New event");

        // NOTE: jobs should be killed fully if any individual event would kill it
        // regardless of future events
        // helps preserve consistency on restarts where events are procesed all at once
        // e.g. do not spin up if job goes below min_rate and then goes above min_rate

        match event {
            DecodedJobEvent::Opened(event) => {
                info!(
                    id = event.job_id,
                    event.metadata,
                    rate = event.rate.to_string(),
                    balance = event.balance.to_string(),
                    timestamp = event.timestamp.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "OPENED",
                );

                // update solvency metrics
                self.balance = event.balance;
                self.rate = event.rate;
                self.original_rate = event.rate;
                self.last_settled = Duration::from_secs(if event.timestamp < 0 {
                    0
                } else {
                    event.timestamp as u64
                });

                if let Err(err) = self.decode_metadata(event.metadata, false) {
                    error!(id = event.job_id, ?err);
                    return JobResult::Failed;
                }

                if !self.allowed_regions.contains(&self.region) {
                    error!(
                        id = event.job_id,
                        self.region, "Region not supported, exiting job"
                    );
                    return JobResult::Failed;
                }

                // blacklist whitelist check
                let allowed =
                    whitelist_blacklist_check(event.owner, address_whitelist, address_blacklist);
                if !allowed {
                    // blacklisted or not whitelisted address
                    return JobResult::Done;
                }

                let mut supported = false;
                for entry in rates {
                    if entry.region == self.region {
                        for card in &entry.rate_cards {
                            if card.instance == self.instance_type {
                                self.min_rate = card.min_rate;
                                supported = true;
                                break;
                            }
                        }
                        break;
                    }
                }

                if !supported {
                    error!(
                        id = event.job_id,
                        self.instance_type, "Instance type not supported",
                    );
                    return JobResult::Failed;
                }

                info!(
                    id = event.job_id,
                    self.instance_type,
                    rate = self.min_rate.to_string(),
                    "MIN RATE",
                );

                // launch only if rate is more than min
                if self.rate >= self.min_rate {
                    for entry in gb_rates {
                        if entry.region_code == self.region {
                            let gb_cost = entry.rate;
                            let bandwidth_rate = self.rate - self.min_rate;

                            self.bandwidth = (bandwidth_rate
                                .saturating_mul(U256::from(1024 * 1024 * 8))
                                / gb_cost)
                                .saturating_to::<u64>();
                            break;
                        }
                    }
                    self.schedule_launch(self.launch_delay);
                    JobResult::Success
                } else {
                    JobResult::Done
                }
            }
            DecodedJobEvent::Settled(event) => {
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );
                // update solvency metrics
                self.balance -= event.amount;
                self.last_settled = Duration::from_secs(if event.timestamp < 0 {
                    0
                } else {
                    event.timestamp as u64
                });
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );

                JobResult::Success
            }
            DecodedJobEvent::Closed(_) => JobResult::Done,
            DecodedJobEvent::Deposited(event) => {
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );
                // update solvency metrics
                self.balance += event.amount;
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );

                JobResult::Success
            }
            DecodedJobEvent::Withdrew(event) => {
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );
                // update solvency metrics
                self.balance -= event.amount;
                info!(
                    id = event.job_id,
                    amount = event.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );

                JobResult::Success
            }
            DecodedJobEvent::ReviseRateInitiated(event) => {
                info!(
                    id = event.job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_INITIATED",
                );
                self.original_rate = self.rate;
                self.rate = event.new_rate;
                if self.rate < self.min_rate {
                    info!(
                        id = event.job_id,
                        "Revised job rate below min rate, shut down"
                    );
                    return JobResult::Done;
                }
                info!(
                    id = event.job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_INITIATED",
                );

                JobResult::Success
            }
            DecodedJobEvent::ReviseRateCancelled(event) => {
                info!(
                    id = event.job_id,
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_CANCELLED",
                );
                self.rate = self.original_rate;
                info!(
                    id = event.job_id,
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_CANCELLED",
                );

                JobResult::Success
            }
            DecodedJobEvent::ReviseRateFinalized(event) => {
                info!(
                    id = event.job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_FINALIZED",
                );
                if self.rate != event.new_rate {
                    error!(
                        id = event.job_id,
                        "Something went wrong, finalized rate not same as initiated rate"
                    );
                    return JobResult::Internal;
                }
                self.original_rate = event.new_rate;
                info!(
                    id = event.job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_FINALIZED",
                );

                JobResult::Success
            }
            DecodedJobEvent::MetadataUpdated(event) => {
                info!(id = event.job_id, event.new_metadata, "METADATA_UPDATED");

                if let Err(err) = self.decode_metadata(event.new_metadata, true) {
                    error!(id = event.job_id, ?err);
                    return JobResult::Failed;
                }

                // schedule change immediately if not already scheduled
                if !self.infra_change_scheduled {
                    self.schedule_launch(0);
                }

                JobResult::Success
            }
        }
    }

    fn decode_metadata(&mut self, metadata: String, update: bool) -> Result<()> {
        let metadata_json =
            serde_json::from_str::<Value>(&metadata).context("Error reading metadata")?;

        let Some(instance) = metadata_json["instance"].as_str() else {
            return Err(anyhow!("Instance type not set"));
        };
        if update && self.instance_type != instance {
            return Err(anyhow!("Instance type change not allowed"));
        } else {
            self.instance_type = instance.to_string();
            info!(self.instance_type, "Instance type set");
        }

        let Some(region) = metadata_json["region"].as_str() else {
            return Err(anyhow!("Job region not set"));
        };
        if update && self.region != region {
            return Err(anyhow!("Region change not allowed"));
        } else {
            self.region = region.to_string();
            info!(self.region, "Job region set");
        }

        let Some(memory) = metadata_json["memory"].as_i64() else {
            return Err(anyhow!("Memory not set"));
        };
        if update && self.req_mem != memory {
            return Err(anyhow!("Memory change not allowed"));
        } else {
            self.req_mem = memory;
            info!(self.req_mem, "Required memory");
        }

        let Some(vcpu) = metadata_json["vcpu"].as_i64() else {
            return Err(anyhow!("vcpu not set"));
        };
        if update && self.req_vcpus != vcpu.try_into().unwrap_or(2) {
            return Err(anyhow!("vcpu change not allowed"));
        } else {
            self.req_vcpus = vcpu.try_into().unwrap_or(i32::MAX);
            info!(self.req_vcpus, "Required vcpu");
        }


        let Some(url) = metadata_json["url"].as_str() else {
            return Err(anyhow!("EIF url not found! Exiting job"));
        };
        self.eif_url = url.to_string();

        let Ok(init_params) =
            BASE64_STANDARD.decode(metadata_json["init_params"].as_str().unwrap_or(""))
        else {
            return Err(anyhow!("failed to decode init params"));
        };
        self.init_params = init_params.into_boxed_slice();

        Ok(())
    }
}

// Registry to track jobs
#[derive(Clone)]
pub struct JobRegistry {
    active_jobs: Arc<Mutex<HashMap<String, Sender<JobEvent>>>>,
    terminated_jobs: Arc<Mutex<HashSet<String>>>,
    db_url: String,
}

impl JobRegistry {
    pub async fn new(db_url: String) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .connect(&db_url)
            .await
            .context("Failed to connect to the DATABASE_URL")?;

        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT job_id FROM terminated_jobs
            "#,
        )
        .fetch_all(&pool)
        .await
        .context("Failed to query terminated jobs ids from the DB")?;

        let terminated_jobs: HashSet<String> = rows.into_iter().map(|(id,)| id).collect();

        info!(
            "Loaded {} terminated jobs from registry",
            terminated_jobs.len()
        );

        Ok(JobRegistry {
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            terminated_jobs: Arc::new(Mutex::new(terminated_jobs)),
            db_url,
        })
    }

    fn add_terminated_job(&self, job_id: String) {
        self.terminated_jobs.lock().unwrap().insert(job_id);
    }

    fn remove_active_job(&self, job_id: String) {
        self.active_jobs.lock().unwrap().remove(&job_id);
    }

    fn is_job_terminated(&self, job_id: &str) -> bool {
        self.terminated_jobs.lock().unwrap().contains(job_id)
    }

    async fn save_to_disk(&self) -> Result<u64> {
        let job_ids: Vec<String> = self
            .terminated_jobs
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();

        if job_ids.is_empty() {
            return Ok(0);
        }

        let pool = PgPoolOptions::new()
            .connect(&self.db_url)
            .await
            .context("Failed to connect to the DATABASE_URL")?;

        let result = sqlx::query(
            r#"
            INSERT INTO terminated_jobs (job_id)
            SELECT * FROM UNNEST ($1::VARCHAR[])
            ON CONFLICT (job_id) DO NOTHING
        "#,
        )
        .bind(&job_ids)
        .execute(&pool)
        .await
        .context("Failed to execute batch insert for terminated_jobs")?;

        Ok(result.rows_affected())
    }

    pub async fn run_periodic_save(self, interval_secs: u64) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            match self.save_to_disk().await {
                Ok(inserted) => {
                    info!("Job registry saved to disk: {} terminated jobs", inserted);
                }
                Err(e) => {
                    error!("Failed to save job registry: {:?}", e);
                }
            }
        }
    }
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  TESTS
// --------------------------------------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use alloy_primitives::hex::FromHex;
    use alloy_primitives::{B256, U256};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration, Instant};

    use crate::market::{self, JobEvent};
    use crate::test::{
        self, compute_address_word, compute_instance_id, Action, TestAws, TestAwsOutcome,
    };

    use super::{JobResult, SystemContext};

    struct TestSystemContext {
        start: Instant,
    }

    impl SystemContext for TestSystemContext {
        fn now_timestamp(&self) -> Duration {
            Instant::now() - self.start
        }
    }

    #[cfg(test)]
    impl market::JobRegistry {
        pub fn new_test() -> Self {
            market::JobRegistry {
                active_jobs: Arc::new(Mutex::new(HashMap::new())),
                terminated_jobs: Arc::new(Mutex::new(HashSet::new())),
                db_url: "db_url".to_string(),
            }
        }
    }

    struct JobManagerParams {
        job_id: market::JobId,
        allowed_regions: Vec<String>,
        address_whitelist: Vec<String>,
        address_blacklist: Vec<String>,
    }

    struct TestResults {
        res: JobResult,
        outcomes: Vec<TestAwsOutcome>,
    }

    async fn run_test(
        start_time: Instant,
        logs: Vec<(u64, Action)>,
        job_manager_params: JobManagerParams,
        test_results: TestResults,
    ) {
        let context = TestSystemContext { start: start_time };

        let job_num = B256::from_hex(&job_manager_params.job_id.id).unwrap();
        let job_logs: Vec<(u64, JobEvent)> = logs
            .into_iter()
            .enumerate()
            .map(|x| (x.1 .0, test::get_event(x.1 .1, x.0 as i64, job_num)))
            .collect();

        let (tx, rx) = mpsc::channel::<JobEvent>(10);
        let mut aws: TestAws = Default::default();
        let job_registry = market::JobRegistry::new_test();

        tokio::spawn(async move {
            for (moment, event) in job_logs {
                let delay = start_time + Duration::from_secs(moment) - Instant::now();
                sleep(delay).await;
                if let Err(err) = tx.send(event).await {
                    println!("{}", err);
                }
            }
        });

        let res = market::job_manager(
            context,
            rx,
            &mut aws,
            job_manager_params.job_id,
            &job_manager_params.allowed_regions,
            300,
            &test::get_rates(),
            &test::get_gb_rates(),
            &job_manager_params.address_whitelist,
            &job_manager_params.address_blacklist,
            12,
            job_registry,
        )
        .await;

        assert!(aws.instances.is_empty());

        assert_eq!(res, test_results.res);
        assert_eq!(aws.outcomes, test_results.outcomes);
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_with_debug_mode_on_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up_with_specific_family() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_deposit_withdraw_settle() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (40, Action::Deposit(500)),
            (60, Action::Withdraw(500)),
            (100, Action::Settle(2, 6)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_cancel() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (50, Action::ReviseRateInitiated(32000000000000u64)),
            (100, Action::ReviseRateFinalized(32000000000000u64)),
            (150, Action::ReviseRateInitiated(60000000000000u64)),
            (200, Action::ReviseRateCancelled),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_region() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-east-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-east-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_region_not_found() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_type_not_found() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_instance() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_url_not_found() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_min_rate() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),29000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_exceed_balance() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,0u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // NOTE: This scenario should be impossible based on how the contract should be written
    // Nevertheless, the cp should handle it to be defensive, so we test
    #[tokio::test(start_paused = true)]
    async fn test_withdrawal_exceed_rate() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (350, Action::Withdraw(30000u64)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_lower_higher() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (350, Action::ReviseRateInitiated(29000000000000u64)),
            (400, Action::ReviseRateFinalized(29000000000000u64)),
            (450, Action::ReviseRateInitiated(31000000000000u64)),
            (500, Action::ReviseRateFinalized(31000000000000u64)),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_whitelisted() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("owner")],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_whitelisted() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("notowner")],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_blacklisted() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("owner")],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_blacklisted() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("notowner")],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // Tests for whitelist blacklist checks
    #[tokio::test]
    async fn test_whitelist_blacklist_check_no_list() {
        let address_whitelist = vec![];
        let address_blacklist = vec![];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_whitelisted() {
        let address_whitelist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_whitelisted() {
        let address_whitelist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_blacklisted() {
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_blacklisted() {
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_neither() {
        let address_whitelist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![
            compute_address_word("definitelynotownereither"),
            compute_address_word("definitelynotowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_both() {
        let address_whitelist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![
            compute_address_word("owner"),
            compute_address_word("definitelynotowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[test]
    fn test_parse_compute_rates() {
        let contents = "[{\"region\": \"ap-south-1\", \"rate_cards\": [{\"instance\": \"c6a.48xlarge\", \"min_rate\": \"2469600000000000000000\", \"cpu\": 192, \"memory\": 384, \"arch\": \"amd64\"}, {\"instance\": \"m7g.xlarge\", \"min_rate\": \"150000000\", \"cpu\": 4, \"memory\": 8, \"arch\": \"arm64\"}]}]";
        let rates: Vec<market::RegionalRates> = serde_json::from_str(contents).unwrap();

        assert_eq!(rates.len(), 1);
        assert_eq!(
            rates[0],
            market::RegionalRates {
                region: "ap-south-1".to_owned(),
                rate_cards: vec![
                    market::RateCard {
                        instance: "c6a.48xlarge".to_owned(),
                        min_rate: U256::from_str_radix("2469600000000000000000", 10).unwrap(),
                        cpu: 192,
                        memory: 384,
                        arch: String::from("amd64")
                    },
                    market::RateCard {
                        instance: "m7g.xlarge".to_owned(),
                        min_rate: U256::from(150000000u64),
                        cpu: 4,
                        memory: 8,
                        arch: String::from("arm64")
                    }
                ]
            }
        );
    }

    #[test]
    fn test_parse_bandwidth_rates() {
        let contents = "[{\"region\": \"Asia South (Mumbai)\", \"region_code\": \"ap-south-1\", \"rate\": \"8264900000000000000000\"}, {\"region\": \"US East (N.Virginia)\", \"region_code\": \"us-east-1\", \"rate\": \"10000\"}]";
        let rates: Vec<market::GBRateCard> = serde_json::from_str(contents).unwrap();

        assert_eq!(rates.len(), 2);
        assert_eq!(
            rates[0],
            market::GBRateCard {
                region: "Asia South (Mumbai)".to_owned(),
                region_code: "ap-south-1".to_owned(),
                rate: U256::from_str_radix("8264900000000000000000", 10).unwrap(),
            }
        );
        assert_eq!(
            rates[1],
            market::GBRateCard {
                region: "US East (N.Virginia)".to_owned(),
                region_code: "us-east-1".to_owned(),
                rate: U256::from(10000u16),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_debug_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            // instance type has also been updated in the metadata. should fail this job.
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(100),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_before_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            // init params have also been updated in the metadata. should fail this job.
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_after_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }
}
