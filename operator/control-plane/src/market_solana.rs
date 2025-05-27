use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use alloy::primitives::U256;
use anchor_lang::{event, AnchorDeserialize, AnchorSerialize, Discriminator};
use anyhow::{Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;
use solana_client::nonblocking::pubsub_client::PubsubClient;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter};
use solana_client::rpc_response::{Response, RpcLogsResponse, RpcResponseContext};
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt;
use tracing::{error, info, info_span, Instrument};

use crate::market::{
    GBRateCard, InfraProvider, JobId, RealSystemContext, RegionalRates, SystemContext,
};

#[event]
#[derive(Debug)]
pub struct JobOpened {
    pub job: Pubkey,
    pub metadata: String,
    pub owner: Pubkey,
    pub provider: Pubkey,
    pub rate: u64,
    pub balance: u64,
    pub timestamp: i64,
}

#[event]
#[derive(Debug)]
pub struct JobSettled {
    pub job: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
#[derive(Debug)]
pub struct JobClosed {
    pub job: Pubkey,
}

#[event]
#[derive(Debug)]
pub struct JobDeposited {
    pub job: Pubkey,
    pub from: Pubkey,
    pub amount: u64,
}

#[event]
#[derive(Debug)]
pub struct JobWithdrew {
    pub job: Pubkey,
    pub token: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
#[derive(Debug)]
pub struct JobRateRevised {
    pub job: Pubkey,
    pub new_rate: u64,
}

#[event]
#[derive(Debug)]
pub struct JobSettlementWithdrawn {
    pub job: Pubkey,
    pub token: Pubkey,
    pub provider: Pubkey,
    pub amount: u64,
}

#[derive(Debug)]
pub enum JobEvent {
    Opened(JobOpened),
    Settled(JobSettled),
    Closed(JobClosed),
    Deposited(JobDeposited),
    Withdrew(JobWithdrew),
    RateRevised(JobRateRevised),
    SettlementWithdrawn(JobSettlementWithdrawn),
}

impl JobEvent {
    pub fn parse_from_log(log: &str) -> Option<Self> {
        if let Some(encoded) = log.strip_prefix("Program data: ") {
            let bytes = BASE64_STANDARD.decode(encoded.trim()).ok()?;

            // Discriminator is first 8 bytes
            let (discriminator, data) = bytes.split_at(8);

            match discriminator {
                JobOpened::DISCRIMINATOR => {
                    return Some(JobEvent::Opened(JobOpened::try_from_slice(data).ok()?))
                }
                JobSettled::DISCRIMINATOR => {
                    return Some(JobEvent::Settled(JobSettled::try_from_slice(data).ok()?))
                }
                JobClosed::DISCRIMINATOR => {
                    return Some(JobEvent::Closed(JobClosed::try_from_slice(data).ok()?))
                }
                JobDeposited::DISCRIMINATOR => {
                    return Some(JobEvent::Deposited(
                        JobDeposited::try_from_slice(data).ok()?,
                    ))
                }
                JobWithdrew::DISCRIMINATOR => {
                    return Some(JobEvent::Withdrew(JobWithdrew::try_from_slice(data).ok()?))
                }
                JobRateRevised::DISCRIMINATOR => {
                    return Some(JobEvent::RateRevised(
                        JobRateRevised::try_from_slice(data).ok()?,
                    ))
                }
                JobSettlementWithdrawn::DISCRIMINATOR => {
                    return Some(JobEvent::SettlementWithdrawn(
                        JobSettlementWithdrawn::try_from_slice(data).ok()?,
                    ))
                }
                _ => return None,
            }
        }

        None
    }
}

pub async fn run(
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    program_id: Pubkey,
    provider: Pubkey,
    rpc_url: String,
    ws_url: String,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    // without job_id.id set
    job_id: JobId,
    job_registry: JobRegistry,
) {
    let mut backoff = 1;

    // connection level loop
    // start from scratch in case of connection errors
    // trying to implicitly resume connections or event streams can cause issues
    // since subscriptions are stateful

    let mut slot = 0;
    loop {
        info!("Connecting to RPC endpoint...");
        let res = PubsubClient::new(&ws_url).await;
        if let Err(err) = res {
            // exponential backoff on connection errors
            error!(?err, "Connection error");
            sleep(Duration::from_secs(backoff)).await;
            backoff *= 2;
            if backoff > 128 {
                backoff = 128;
            }
            continue;
        }
        backoff = 1;
        info!("Connected to RPC endpoint");

        let client = res.unwrap();

        // register subscription
        let stream = client
            .logs_subscribe(
                RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]),
                RpcTransactionLogsConfig {
                    commitment: Some(CommitmentConfig::confirmed()),
                },
            )
            .await
            .context("failed to subscribe to new jobs");
        if let Err(err) = stream {
            error!(?err, "Subscribe error");
            sleep(Duration::from_secs(1)).await;
            continue;
        };
        let (stream, _) = stream.unwrap();

        let rpc_client = RpcClient::new(rpc_url.to_owned());
        // get cutoff slot number
        let cutoff = rpc_client
            .get_slot()
            .await
            .context("failed to get cutoff slot");
        if let Err(err) = cutoff {
            error!(?err, "RPC error");
            sleep(Duration::from_secs(1)).await;
            continue;
        };
        let cutoff = cutoff.unwrap();

        // cut off stream at cutoff slot
        let stream = stream.filter_map(move |item| {
            if item.context.slot > cutoff {
                Some(item)
            } else {
                None
            }
        });

        let old_logs =
            get_logs_for_program_between_slots(&rpc_client, program_id, slot, cutoff).await;
        if let Err(err) = old_logs {
            error!(?err, "RPC error");
            sleep(Duration::from_secs(1)).await;
            continue;
        };
        let old_logs = tokio_stream::iter(old_logs.unwrap());

        // market stream
        let stream = old_logs.chain(stream);

        let job_stream = std::pin::pin!(stream);
        slot = run_once(
            // we need to keep track of jobs for whom tasks have already been spawned
            // and not spawn duplicate tasks
            job_stream,
            infra_provider.clone(),
            slot,
            provider,
            regions,
            rates,
            gb_rates,
            address_whitelist,
            address_blacklist,
            job_id.clone(),
            job_registry.clone(),
        )
        .await;
    }
}

// Get historical logs for the market program
pub async fn get_logs_for_program_between_slots(
    client: &RpcClient,
    program_id: Pubkey,
    last_slot: u64,
    current_slot: u64,
) -> Result<Vec<Response<RpcLogsResponse>>> {
    let mut collected_logs = Vec::new();
    let mut before = None;

    loop {
        let config = GetConfirmedSignaturesForAddress2Config {
            before,
            until: None,
            limit: Some(1000),
            commitment: Some(CommitmentConfig {
                commitment: CommitmentLevel::Confirmed,
            }),
        };

        let batch = client
            .get_signatures_for_address_with_config(&program_id, config)
            .await
            .context("failed to get historical signatures for market program")?;

        if batch.is_empty() {
            break;
        }

        let batch_len = batch.len();

        for signature_info in batch {
            let signature =
                Signature::from_str(&signature_info.signature).context("invalid signature")?;
            let tx = client
                .get_transaction(&signature, UiTransactionEncoding::Json)
                .await
                .context("failed to get transaction data")?;
            before = Some(signature);

            let slot = tx.slot;
            if slot > current_slot {
                continue;
            }
            if slot < last_slot {
                break;
            }

            collected_logs.push(Response {
                context: RpcResponseContext {
                    slot: slot,
                    api_version: None,
                },
                value: RpcLogsResponse {
                    signature: signature_info.signature,
                    err: signature_info.err,
                    logs: tx
                        .transaction
                        .meta
                        .and_then(|meta| Some(meta.log_messages.unwrap_or(vec![])))
                        .unwrap_or_default(),
                },
            });
        }

        if batch_len < 1000 {
            break;
        }
    }

    collected_logs.reverse();

    Ok(collected_logs)
}

async fn run_once(
    mut job_stream: impl StreamExt<Item = Response<RpcLogsResponse>> + Unpin,
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    slot: u64,
    provider: Pubkey,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    // without job_id.id set
    job_id: JobId,
    job_registry: JobRegistry,
) -> u64 {
    let mut current_slot = slot;

    while let Some(log) = job_stream.next().await {
        for log in log.value.logs {
            let Some(job_event) = JobEvent::parse_from_log(&log) else {
                continue;
            };

            // handle event logs accordingly
            match job_event {
                JobEvent::Opened(event) => {
                    if event.provider != provider {
                        continue;
                    }

                    let job = event.job;
                    info!(?job, "New job");

                    let job_registry = job_registry.clone();

                    // prepare with correct job id
                    let mut job_id = job_id.clone();
                    job_id.id = job.to_string();

                    // Skip if this job has already been terminated
                    if job_registry.is_job_terminated(&job_id.id) {
                        info!("Skipping already terminated job: {}", job_id.id);
                        continue;
                    }

                    if job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .contains_key(&job_id.id)
                    {
                        info!("Skipping already running job: {}", job_id.id);
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
                            job_registry,
                        )
                        .instrument(info_span!(parent: None, "job", ?job)),
                    );

                    let _ = tx.send(JobEvent::Opened(event)).await;
                }
                JobEvent::Settled(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::Settled(event)).await;
                    }
                }
                JobEvent::Closed(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::Closed(event)).await;
                    }
                }
                JobEvent::Deposited(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::Deposited(event)).await;
                    }
                }
                JobEvent::Withdrew(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::Withdrew(event)).await;
                    }
                }
                JobEvent::RateRevised(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::RateRevised(event)).await;
                    }
                }
                JobEvent::SettlementWithdrawn(event) => {
                    if let Some(tx) = job_registry
                        .active_jobs
                        .lock()
                        .unwrap()
                        .get(&event.job.to_string())
                    {
                        let _ = tx.send(JobEvent::SettlementWithdrawn(event)).await;
                    }
                }
            }
        }

        current_slot = log.context.slot;
    }

    info!("Job stream ended");

    current_slot
}

fn whitelist_blacklist_check(
    owner: Pubkey,
    address_whitelist: &[String],
    address_blacklist: &[String],
) -> bool {
    // check whitelist
    if !address_whitelist.is_empty() {
        info!("Checking address whitelist...");
        if address_whitelist.iter().any(|s| s == &owner.to_string()) {
            info!("ADDRESS ALLOWED!");
        } else {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        }
    }

    // check blacklist
    if !address_blacklist.is_empty() {
        info!("Checking address blacklist...");
        if address_blacklist.iter().any(|s| s == &owner.to_string()) {
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

    balance: u64,
    last_settled: Duration,
    rate: u64,
    original_rate: u64,
    family: String,
    min_rate: U256,
    bandwidth: u64,
    eif_url: String,
    instance_type: String,
    region: String,
    req_vcpus: i32,
    req_mem: i64,
    debug: bool,
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
            balance: 360,
            last_settled: context.now_timestamp(),
            rate: 1,
            original_rate: 1,
            // salmon is the default for jobs (usually old) without any family specified
            family: "salmon".to_owned(),
            min_rate: U256::MAX,
            bandwidth: 0,
            eif_url: String::new(),
            instance_type: "c6a.xlarge".to_string(),
            region: "ap-south-1".to_string(),
            req_vcpus: 2,
            req_mem: 4096,
            debug: false,
            init_params: Box::new([0; 0]),
            infra_state: false,
            infra_change_time: Instant::now(),
            infra_change_scheduled: false,
        }
    }

    fn insolvency_duration(&self) -> Duration {
        let now_ts = self.context.now_timestamp();

        if self.rate == 0 {
            Duration::from_secs(0)
        } else {
            // solvent for balance / rate seconds from last_settled with 300s as margin
            Duration::from_secs((self.balance * 10u64.pow(12) / self.rate).saturating_sub(300))
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
                    self.family.as_str(),
                    &self.region,
                    self.req_mem,
                    self.req_vcpus,
                    self.bandwidth,
                    &self.eif_url,
                    self.debug,
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
            let res = infra_provider.spin_down(&self.job_id, &self.region).await;
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
    // JobResult::Retry on recoverable errors, usually networking
    // JobResult::Failed on unrecoverable errors
    // JobResult::Internal on internal errors, usually bugs
    fn process_log(
        &mut self,
        log: Option<JobEvent>,
        rates: &[RegionalRates],
        gb_rates: &[GBRateCard],
        address_whitelist: &[String],
        address_blacklist: &[String],
    ) -> JobResult {
        let Some(log) = log else {
            // error in the stream, can retry with new conn
            return JobResult::Retry;
        };
        info!(event = ?log, "New log");

        // NOTE: jobs should be killed fully if any individual event would kill it
        // regardless of future events
        // helps preserve consistency on restarts where events are procesed all at once
        // e.g. do not spin up if job goes below min_rate and then goes above min_rate

        match log {
            JobEvent::Opened(log) => {
                info!(
                    log.metadata,
                    rate = log.rate,
                    balance = log.balance,
                    timestamp = log.timestamp,
                    last_settled = self.last_settled.as_secs(),
                    "OPENED",
                );

                // update solvency metrics
                self.balance = log.balance;
                self.rate = log.rate;
                self.original_rate = log.rate;
                self.last_settled = Duration::from_secs(log.timestamp as u64);

                let Ok(v) = serde_json::from_str::<Value>(&log.metadata)
                    .inspect_err(|err| error!(?err, "Error reading metadata"))
                else {
                    return JobResult::Failed;
                };

                let Some(t) = v["instance"].as_str() else {
                    error!("Instance type not set");
                    return JobResult::Failed;
                };
                self.instance_type = t.to_string();
                info!(self.instance_type, "Instance type set");

                let Some(t) = v["region"].as_str() else {
                    error!("Job region not set");
                    return JobResult::Failed;
                };
                self.region = t.to_string();
                info!(self.region, "Job region set");

                if !self.allowed_regions.contains(&self.region) {
                    error!(self.region, "Region not suppported, exiting job");
                    return JobResult::Failed;
                }

                let Some(t) = v["memory"].as_i64() else {
                    error!("Memory not set");
                    return JobResult::Failed;
                };
                self.req_mem = t;
                info!(self.req_mem, "Required memory");

                let Some(t) = v["vcpu"].as_i64() else {
                    error!("vcpu not set");
                    return JobResult::Failed;
                };
                self.req_vcpus = t.try_into().unwrap_or(i32::MAX);
                info!(self.req_vcpus, "Required vcpu");

                let Some(url) = v["url"].as_str() else {
                    error!("EIF url not found! Exiting job");
                    return JobResult::Failed;
                };
                self.eif_url = url.to_string();

                // we leave the default family unchanged if not found for backward compatibility
                v["family"]
                    .as_str()
                    .inspect(|f| self.family = (*f).to_owned());

                // we leave the default debug mode unchanged if not found for backward compatibility
                v["debug"].as_bool().inspect(|f| self.debug = *f);

                let Ok(init_params) =
                    BASE64_STANDARD.decode(v["init_params"].as_str().unwrap_or(""))
                else {
                    error!("failed to decode init params");
                    return JobResult::Failed;
                };
                self.init_params = init_params.into_boxed_slice();

                // blacklist whitelist check
                let allowed =
                    whitelist_blacklist_check(log.owner, address_whitelist, address_blacklist);
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
                    error!(self.instance_type, "Instance type not supported",);
                    return JobResult::Failed;
                }

                info!(
                    self.instance_type,
                    rate = self.min_rate.to_string(),
                    "MIN RATE",
                );

                // launch only if rate is more than min
                if U256::from(self.rate) >= self.min_rate {
                    for entry in gb_rates {
                        if entry.region_code == self.region {
                            let gb_cost = entry.rate;
                            let bandwidth_rate = U256::from(self.rate) - self.min_rate;

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
            JobEvent::Settled(log) => {
                info!(
                    amount = log.amount,
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );
                // update solvency metrics
                self.balance -= log.amount;
                self.last_settled = Duration::from_secs(log.timestamp as u64);
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );

                return JobResult::Success;
            }
            JobEvent::Closed(_log) => {
                return JobResult::Done;
            }
            JobEvent::Deposited(log) => {
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );
                // update solvency metrics
                self.balance += log.amount;
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );

                return JobResult::Success;
            }
            JobEvent::Withdrew(log) => {
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );
                // update solvency metrics
                self.balance -= log.amount;
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );

                return JobResult::Success;
            }
            JobEvent::SettlementWithdrawn(log) => {
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLEMENT_WITHDRAW",
                );
                // update solvency metrics
                self.balance -= log.amount;
                info!(
                    amount = log.amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );

                return JobResult::Success;
            }
            JobEvent::RateRevised(log) => {
                info!(
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_RATE_REVISED",
                );
                self.original_rate = log.new_rate;
                self.rate = log.new_rate;
                if U256::from(self.rate) < self.min_rate {
                    info!("Revised job rate below min rate, shut down");
                    return JobResult::Done;
                }
                info!(
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_RATE_REVISED",
                );

                return JobResult::Success;
            }
        }
    }
}

// Registry to track jobs
#[derive(Clone)]
pub struct JobRegistry {
    pub active_jobs: Arc<Mutex<HashMap<String, mpsc::Sender<JobEvent>>>>,
    terminated_jobs: Arc<Mutex<HashSet<String>>>,
    save_path: String,
}

impl JobRegistry {
    pub async fn new(save_path: String) -> Result<Self> {
        let mut terminated_jobs = HashSet::new();
        // Initialize with jobs from disk if file exists
        if Path::new(&save_path).exists() {
            terminated_jobs = fs::read_to_string(&save_path)
                .await?
                .trim()
                .lines()
                .map(str::to_owned)
                .collect();
            info!(
                "Loaded {} terminated jobs from registry",
                terminated_jobs.len()
            );
        }

        Ok(JobRegistry {
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            terminated_jobs: Arc::new(Mutex::new(terminated_jobs)),
            save_path,
        })
    }

    fn add_terminated_job(&self, job_id: String) {
        self.active_jobs.lock().unwrap().remove(&job_id);
        self.terminated_jobs.lock().unwrap().insert(job_id);
    }

    fn is_job_terminated(&self, job_id: &str) -> bool {
        self.terminated_jobs.lock().unwrap().contains(job_id)
    }

    async fn save_to_disk(&self) -> Result<(), std::io::Error> {
        let jobs = self
            .terminated_jobs
            .lock()
            .unwrap()
            .iter()
            .fold("".to_owned(), |a, b| a + "\n" + b)
            .trim()
            .to_owned();
        fs::write(&self.save_path, jobs).await?;
        Ok(())
    }

    pub async fn run_periodic_save(self, interval_secs: u64) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            if let Err(e) = self.save_to_disk().await {
                error!("Failed to save job registry: {:?}", e);
            } else {
                info!(
                    "Job registry saved to disk: {} terminated jobs",
                    self.terminated_jobs.lock().unwrap().len()
                );
            }
        }
    }
}

#[derive(PartialEq, Debug)]
enum JobResult {
    // success
    Success,
    // done, should still terminate instance, if any
    Done,
    // error, can retry with a new conn
    Retry,
    // error, should terminate instance, if any
    Failed,
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
    job_registry: JobRegistry,
) -> JobResult {
    let mut state = JobState::new(&context, job_id, aws_delay_duration, allowed_regions);

    // usually tracks the result of the last log processed
    let mut job_result = JobResult::Success;

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
        let insolvency_duration = state.insolvency_duration();
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
                use JobResult::*;
                job_result = state.process_log(log, rates, gb_rates, address_whitelist, address_blacklist);
                match job_result {
                    // just proceed
                    Success => {},
                    // terminate
                    Done => {
                        state.schedule_termination(0);
                    },
                    // break and eventually retry
                    Retry => continue,
                    // terminate
                    Failed => {
                        state.schedule_termination(0);
                    },
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

    job_registry.add_terminated_job(state.job_id.id.clone());

    job_result
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  TESTS
// --------------------------------------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use solana_sdk::pubkey::Pubkey;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration, Instant};

    use crate::market_solana::{
        JobClosed, JobDeposited, JobOpened, JobRateRevised, JobSettled, JobWithdrew,
    };
    use crate::test::{self, compute_address_word, compute_instance_id, TestAws, TestAwsOutcome};
    use crate::{market, market_solana};

    use super::{JobEvent, JobResult, SystemContext};

    struct TestSystemContext {
        start: Instant,
    }

    impl SystemContext for TestSystemContext {
        fn now_timestamp(&self) -> Duration {
            Instant::now() - self.start
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
        logs: Vec<(u64, JobEvent)>,
        job_manager_params: JobManagerParams,
        test_results: TestResults,
    ) {
        let context = TestSystemContext { start: start_time };

        let (tx, rx) = mpsc::channel::<JobEvent>(100);
        let mut aws: TestAws = Default::default();
        let job_registry = market_solana::JobRegistry::new("terminated_jobs.txt".to_string())
            .await
            .unwrap();

        tokio::spawn(async move {
            for (moment, event) in logs {
                let delay = start_time + Duration::from_secs(moment) - Instant::now();
                sleep(delay).await;
                let _ = tx.send(event).await;
            }
        });

        let res = market_solana::job_manager(
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
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (301, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (301, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_with_debug_mode_on_spin_up() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (301, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: true,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up_with_specific_family() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"family\":\"tuna\"}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (301, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "tuna".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_deposit_withdraw_settle() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (40, JobEvent::Deposited(JobDeposited {
                job: job_id,
                from: Pubkey::new_from_array(compute_address_word("depositor").0),
                amount: 500,
            })),
            (60, JobEvent::Withdrew(JobWithdrew {
                job: job_id,
                token: Pubkey::new_from_array(compute_address_word("token").0),
                to: Pubkey::new_from_array(compute_address_word("withdrawer").0),
                amount: 500,
            })),
            (100, JobEvent::Settled(JobSettled {
                job: job_id,
                amount: 2,
                timestamp: 6,
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_cancel() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (50, JobEvent::RateRevised(JobRateRevised {
                job: job_id,
                new_rate: 32000000000000u64,
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_region() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-east-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-east-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_region_not_found() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_type_not_found() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_instance() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_url_not_found() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_min_rate() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 29000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_exceed_balance() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 0u64,
                timestamp: 0
            })),
            (505, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                job: job_id.to_string(),
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
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (350, JobEvent::Withdrew(JobWithdrew { job: job_id, token: Pubkey::new_from_array(compute_address_word("token").0), to: Pubkey::new_from_array(compute_address_word("withdrawer").0), amount: 30000u64 })),
            (500, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_lower_higher() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (350, JobEvent::RateRevised(JobRateRevised {
                job: job_id,
                new_rate: 29000000000000u64,
            })),
            (450, JobEvent::RateRevised(JobRateRevised {
                job: job_id,
                new_rate: 31000000000000u64,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
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
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_whitelisted() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (500, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![
                Pubkey::new_from_array(compute_address_word("owner").0).to_string()
            ],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_whitelisted() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (500, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![
                Pubkey::new_from_array(compute_address_word("notowner").0).to_string()
            ],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_blacklisted() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (500, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![
                Pubkey::new_from_array(compute_address_word("owner").0).to_string()
            ],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_blacklisted() {
        let start_time = Instant::now();
        let job_id = Pubkey::new_unique();

        let logs = vec![
            (0, JobEvent::Opened(JobOpened {
                job: job_id,
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: Pubkey::new_from_array(compute_address_word("owner").0), 
                provider: Pubkey::new_from_array(compute_address_word("provider").0),
                rate: 31000000000000u64,
                balance: 31000u64,
                timestamp: 0
            })),
            (500, JobEvent::Closed(JobClosed {
                job: job_id,
            })),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![
                Pubkey::new_from_array(compute_address_word("notowner").0).to_string()
            ],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // Tests for whitelist blacklist checks
    #[tokio::test]
    async fn test_whitelist_blacklist_check_no_list() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_whitelisted() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![
            owner.to_string(),
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
        ];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_whitelisted() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
            Pubkey::new_from_array(compute_address_word("notownereither").0).to_string(),
        ];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(!market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_blacklisted() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![];
        let address_blacklist = vec![
            Pubkey::new_from_array(compute_address_word("owner").0).to_string(),
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_blacklisted() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![];
        let address_blacklist = vec![
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
            Pubkey::new_from_array(compute_address_word("notownereither").0).to_string(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_neither() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![
            Pubkey::new_from_array(compute_address_word("notownereither").0).to_string(),
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
        ];
        let address_blacklist = vec![
            Pubkey::new_from_array(compute_address_word("definitelynotownereither").0).to_string(),
            Pubkey::new_from_array(compute_address_word("definitelynotowner").0).to_string(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_both() {
        let owner = Pubkey::new_from_array(compute_address_word("owner").0);
        let address_whitelist = vec![
            Pubkey::new_from_array(compute_address_word("owner").0).to_string(),
            Pubkey::new_from_array(compute_address_word("notowner").0).to_string(),
        ];
        let address_blacklist = vec![
            Pubkey::new_from_array(compute_address_word("owner").0).to_string(),
            Pubkey::new_from_array(compute_address_word("definitelynotowner").0).to_string(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market_solana::whitelist_blacklist_check(
            owner,
            &address_whitelist,
            &address_blacklist
        ));
    }
}
