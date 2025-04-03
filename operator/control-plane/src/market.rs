use std::collections::HashSet;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use alloy::hex::ToHexExt;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::pubsub::PubSubFrontend;
use alloy::rpc::types::eth::{Filter, Log};
use alloy::sol_types::SolValue;
use alloy::transports::ws::WsConnect;
use anyhow::{Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::fs;
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt;
use tracing::{error, info, info_span, Instrument};

// IMPORTANT: do not import SystemTime, use a SystemContext

// Trait to encapsulate behaviour that should be simulated in tests
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
        family: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        debug: bool,
        init_params: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    fn spin_down(&mut self, job: &JobId, region: &str) -> impl Future<Output = Result<()>> + Send;

    fn get_job_ip(&self, job: &JobId, region: &str) -> impl Future<Output = Result<String>> + Send;

    fn check_enclave_running(
        &mut self,
        job: &JobId,
        region: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl<'a, T> InfraProvider for &'a mut T
where
    T: InfraProvider + Send + Sync,
{
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        family: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        debug: bool,
        init_params: &[u8],
    ) -> Result<()> {
        (**self)
            .spin_up(
                job,
                instance_type,
                family,
                region,
                req_mem,
                req_vcpu,
                bandwidth,
                image_url,
                debug,
                init_params,
            )
            .await
    }

    async fn spin_down(&mut self, job: &JobId, region: &str) -> Result<()> {
        (**self).spin_down(job, region).await
    }

    async fn get_job_ip(&self, job: &JobId, region: &str) -> Result<String> {
        (**self).get_job_ip(job, region).await
    }

    async fn check_enclave_running(&mut self, job: &JobId, region: &str) -> Result<bool> {
        (**self).check_enclave_running(job, region).await
    }
}

pub trait LogsProvider {
    fn new_jobs<'a>(
        &'a self,
        client: &'a impl Provider<PubSubFrontend>,
    ) -> impl Future<Output = Result<impl StreamExt<Item = (B256, bool)> + 'a>>;

    fn job_logs<'a>(
        &'a self,
        client: &'a impl Provider<PubSubFrontend>,
        job: B256,
    ) -> impl Future<Output = Result<impl StreamExt<Item = Log> + Send + 'a>> + Send;
}

#[derive(Clone)]
pub struct EthersProvider {
    pub contract: Address,
    pub provider: Address,
}

impl LogsProvider for EthersProvider {
    async fn new_jobs<'a>(
        &'a self,
        client: &'a impl Provider<PubSubFrontend>,
    ) -> Result<impl StreamExt<Item = (B256, bool)> + 'a> {
        new_jobs(client, self.contract, self.provider).await
    }

    async fn job_logs<'a>(
        &'a self,
        client: &'a impl Provider<PubSubFrontend>,
        job: B256,
    ) -> Result<impl StreamExt<Item = Log> + Send + 'a> {
        job_logs(client, self.contract, job).await
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

pub async fn run(
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    logs_provider: impl LogsProvider + Send + Sync + Clone + 'static,
    url: String,
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

    let mut job_count = 0;
    loop {
        info!("Connecting to RPC endpoint...");
        let res = ProviderBuilder::new()
            .on_ws(WsConnect::new(url.clone()))
            .await;
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
        let res = logs_provider.new_jobs(&client).await;
        if let Err(err) = res {
            error!(?err, "Subscribe error");
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let job_stream = std::pin::pin!(res.unwrap());
        job_count += run_once(
            // we need to keep track of jobs for whom tasks have already been spawned
            // and not spawn duplicate tasks
            job_stream.skip(job_count),
            infra_provider.clone(),
            logs_provider.clone(),
            url.clone(),
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

async fn run_once(
    mut job_stream: impl StreamExt<Item = (B256, bool)> + Unpin,
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    logs_provider: impl LogsProvider + Send + Sync + Clone + 'static,
    url: String,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    // without job_id.id set
    job_id: JobId,
    job_registry: JobRegistry,
) -> usize {
    let mut job_count = 0;
    while let Some((job, removed)) = job_stream.next().await {
        info!(?job, removed, "New job");

        let job_registry = job_registry.clone();

        // prepare with correct job id
        let mut job_id = job_id.clone();
        job_id.id = job.encode_hex_with_prefix();

        // Skip if this job has already been terminated
        if job_registry.is_job_terminated(&job_id.id) {
            info!("Skipping already terminated job: {}", job_id.id);
            job_count += 1;
            continue;
        }

        tokio::spawn(
            job_manager(
                infra_provider.clone(),
                logs_provider.clone(),
                url.clone(),
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
        job_count += 1;
    }

    info!("Job stream ended");

    job_count
}

async fn new_jobs(
    client: &impl Provider<PubSubFrontend>,
    address: Address,
    provider: Address,
) -> Result<impl StreamExt<Item = (B256, bool)> + '_> {
    let event_filter = Filter::new()
        .address(address)
        .event_signature(vec![keccak256(
            "JobOpened(bytes32,string,address,address,uint256,uint256,uint256)",
        )])
        .topic3(provider.into_word());

    // ordering is important to prevent race conditions while getting all logs but
    // it still relies on the RPC being consistent between registering the subscription
    // and querying the cutoff block number

    // register subscription
    let stream = client
        .subscribe_logs(&event_filter.clone().select(0..))
        .await
        .context("failed to subscribe to new jobs")?
        .into_stream();

    // get cutoff block number
    let cutoff = client
        .get_block_number()
        .await
        .context("failed to get cutoff block")?;

    // cut off stream at cutoff block, extract data from items
    let stream = stream.filter_map(move |item| {
        if item.block_number.unwrap() > cutoff {
            Some((item.topics()[1], item.removed))
        } else {
            None
        }
    });

    // get logs up to cutoff
    let old_logs = client
        .get_logs(&event_filter.select(0..=cutoff))
        .await
        .context("failed to query old logs")?;

    // convert to a stream, extract data from items
    let old_logs = tokio_stream::iter(old_logs).map(|item| (item.topics()[1], item.removed));

    // stream
    let stream = old_logs.chain(stream);

    Ok(stream)
}

// manage the complete lifecycle of a job
async fn job_manager(
    infra_provider: impl InfraProvider + Send + Sync + Clone,
    logs_provider: impl LogsProvider + Send + Sync,
    url: String,
    job_id: JobId,
    allowed_regions: &[String],
    aws_delay_duration: u64,
    rates: &[RegionalRates],
    gb_rates: &[GBRateCard],
    address_whitelist: &[String],
    address_blacklist: &[String],
    job_registry: JobRegistry,
) {
    let mut backoff = 1;
    let job = job_id.id.clone();

    // connection level loop
    // start from scratch in case of connection errors
    // trying to implicitly resume connections or event streams can cause issues
    // since subscriptions are stateful
    loop {
        info!("Connecting to RPC endpoint...");
        let res = ProviderBuilder::new()
            .on_ws(WsConnect::new(url.clone()))
            .await;
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
        let res = logs_provider
            // TODO: Bad unwrap?
            .job_logs(&client, job.parse().unwrap())
            .await;
        if let Err(err) = res {
            error!(?err, "Subscribe error");
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let job_stream = std::pin::pin!(res.unwrap());
        let res = job_manager_once(
            RealSystemContext {},
            job_stream,
            infra_provider.clone(),
            job_id.clone(),
            allowed_regions,
            aws_delay_duration,
            rates,
            gb_rates,
            address_whitelist,
            address_blacklist,
        )
        .await;

        if res == JobResult::Done || res == JobResult::Failed {
            job_registry.add_terminated_job(job_id.id.clone());
        }

        if res != JobResult::Retry {
            // full exit
            break;
        }
    }
}

fn whitelist_blacklist_check(
    log: Log,
    address_whitelist: &[String],
    address_blacklist: &[String],
) -> bool {
    // check whitelist
    if !address_whitelist.is_empty() {
        info!("Checking address whitelist...");
        if address_whitelist
            .iter()
            .any(|s| s == &log.topics()[2].encode_hex_with_prefix())
        {
            info!("ADDRESS ALLOWED!");
        } else {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        }
    }

    // check blacklist
    if !address_blacklist.is_empty() {
        info!("Checking address blacklist...");
        if address_blacklist
            .iter()
            .any(|s| s == &log.topics()[2].encode_hex_with_prefix())
        {
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
            balance: U256::from(360),
            last_settled: context.now_timestamp(),
            rate: U256::from(1),
            original_rate: U256::from(1),
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

        if self.rate == U256::ZERO {
            Duration::from_secs(0)
        } else {
            // solvent for balance / rate seconds from last_settled with 300s as margin
            Duration::from_secs(
                (self.balance * U256::from(10).pow(U256::from(12)) / self.rate)
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
        log: Option<Log>,
        rates: &[RegionalRates],
        gb_rates: &[GBRateCard],
        address_whitelist: &[String],
        address_blacklist: &[String],
    ) -> JobResult {
        let Some(log) = log else {
            // error in the stream, can retry with new conn
            return JobResult::Retry;
        };
        info!(topic = ?log.topics()[0], data = ?log.data(), "New log");

        // events
        #[allow(non_snake_case)]
        let JOB_OPENED =
            keccak256("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)");
        #[allow(non_snake_case)]
        let JOB_SETTLED = keccak256("JobSettled(bytes32,uint256,uint256)");
        #[allow(non_snake_case)]
        let JOB_CLOSED = keccak256("JobClosed(bytes32)");
        #[allow(non_snake_case)]
        let JOB_DEPOSITED = keccak256("JobDeposited(bytes32,address,uint256)");
        #[allow(non_snake_case)]
        let JOB_WITHDREW = keccak256("JobWithdrew(bytes32,address,uint256)");
        #[allow(non_snake_case)]
        let JOB_REVISE_RATE_INITIATED = keccak256("JobReviseRateInitiated(bytes32,uint256)");
        #[allow(non_snake_case)]
        let JOB_REVISE_RATE_CANCELLED = keccak256("JobReviseRateCancelled(bytes32)");
        #[allow(non_snake_case)]
        let JOB_REVISE_RATE_FINALIZED = keccak256("JobReviseRateFinalized(bytes32,uint256)");
        #[allow(non_snake_case)]
        let METADATA_UPDATED = keccak256("JobMetadataUpdated(bytes32,string)");

        // NOTE: jobs should be killed fully if any individual event would kill it
        // regardless of future events
        // helps preserve consistency on restarts where events are procesed all at once
        // e.g. do not spin up if job goes below min_rate and then goes above min_rate

        if log.topics()[0] == JOB_OPENED {
            // decode
            let Ok((metadata, _rate, _balance, timestamp)) =
                <(String, U256, U256, U256)>::abi_decode_sequence(&log.data().data, true)
                    .inspect_err(|err| error!(?err, data = ?log.data(), "OPENED: Decode failure"))
            else {
                return JobResult::Internal;
            };

            info!(
                metadata,
                rate = _rate.to_string(),
                balance = _balance.to_string(),
                timestamp = timestamp.to_string(),
                last_settled = self.last_settled.as_secs(),
                "OPENED",
            );

            // update solvency metrics
            self.balance = _balance;
            self.rate = _rate;
            self.original_rate = _rate;
            self.last_settled = Duration::from_secs(timestamp.saturating_to::<u64>());

            let Ok(v) = serde_json::from_str::<Value>(&metadata)
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

            let Ok(init_params) = BASE64_STANDARD.decode(v["init_params"].as_str().unwrap_or(""))
            else {
                error!("failed to decode init params");
                return JobResult::Failed;
            };
            self.init_params = init_params.into_boxed_slice();

            // blacklist whitelist check
            let allowed =
                whitelist_blacklist_check(log.clone(), address_whitelist, address_blacklist);
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
            if self.rate >= self.min_rate {
                for entry in gb_rates {
                    if entry.region_code == self.region {
                        let gb_cost = entry.rate;
                        let bandwidth_rate = self.rate - self.min_rate;

                        self.bandwidth =
                            (bandwidth_rate.saturating_mul(U256::from(1024 * 1024 * 8)) / gb_cost)
                                .saturating_to::<u64>();
                        break;
                    }
                }
                self.schedule_launch(self.launch_delay);
                JobResult::Success
            } else {
                JobResult::Done
            }
        } else if log.topics()[0] == JOB_SETTLED {
            // decode
            let Ok((amount, timestamp)) =
                <(U256, U256)>::abi_decode_sequence(&log.data().data, true)
                    .inspect_err(|err| error!(?err, data = ?log.data(), "SETTLED: Decode failure"))
            else {
                return JobResult::Internal;
            };

            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "SETTLED",
            );
            // update solvency metrics
            self.balance -= amount;
            self.last_settled = Duration::from_secs(timestamp.saturating_to::<u64>());
            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "SETTLED",
            );

            return JobResult::Success;
        } else if log.topics()[0] == JOB_CLOSED {
            return JobResult::Done;
        } else if log.topics()[0] == JOB_DEPOSITED {
            // decode
            // IMPORTANT: Tuples have to be decoded using abi_decode_sequence
            // if this is changed in the future
            let Ok(amount) = U256::abi_decode(&log.data().data, true)
                .inspect_err(|err| error!(?err, data = ?log.data(), "DEPOSITED: Decode failure"))
            else {
                return JobResult::Internal;
            };

            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "DEPOSITED",
            );
            // update solvency metrics
            self.balance += amount;
            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "DEPOSITED",
            );

            return JobResult::Success;
        } else if log.topics()[0] == JOB_WITHDREW {
            // decode
            // IMPORTANT: Tuples have to be decoded using abi_decode_sequence
            // if this is changed in the future
            let Ok(amount) = U256::abi_decode(&log.data().data, true)
                .inspect_err(|err| error!(?err, data = ?log.data(), "WITHDREW: Decode failure"))
            else {
                return JobResult::Internal;
            };

            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "WITHDREW",
            );
            // update solvency metrics
            self.balance -= amount;
            info!(
                amount = amount.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "WITHDREW",
            );

            return JobResult::Success;
        } else if log.topics()[0] == JOB_REVISE_RATE_INITIATED {
            // IMPORTANT: Tuples have to be decoded using abi_decode_sequence
            // if this is changed in the future
            let Ok(new_rate) = U256::abi_decode(&log.data().data, true).inspect_err(
                |err| error!(?err, data = ?log.data(), "JOB_REVISE_RATE_INTIATED: Decode failure"),
            ) else {
                return JobResult::Internal;
            };

            info!(
                self.original_rate = self.original_rate.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_INTIATED",
            );
            self.original_rate = self.rate;
            self.rate = new_rate;
            if self.rate < self.min_rate {
                info!("Revised job rate below min rate, shut down");
                return JobResult::Done;
            }
            info!(
                self.original_rate = self.original_rate.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_INTIATED",
            );

            return JobResult::Success;
        } else if log.topics()[0] == JOB_REVISE_RATE_CANCELLED {
            info!(
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_CANCELLED",
            );
            self.rate = self.original_rate;
            info!(
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_CANCELLED",
            );

            return JobResult::Success;
        } else if log.topics()[0] == JOB_REVISE_RATE_FINALIZED {
            // IMPORTANT: Tuples have to be decoded using abi_decode_sequence
            // if this is changed in the future
            let Ok(new_rate) = U256::abi_decode(&log.data().data, true).inspect_err(
                |err| error!(?err, data = ?log.data(), "JOB_REVISE_RATE_FINALIZED: Decode failure"),
            ) else {
                return JobResult::Internal;
            };

            info!(
                self.original_rate = self.original_rate.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_FINALIZED",
            );
            if self.rate != new_rate {
                error!("Something went wrong, finalized rate not same as initiated rate");
                return JobResult::Internal;
            }
            self.original_rate = new_rate;
            info!(
                self.original_rate = self.original_rate.to_string(),
                rate = self.rate.to_string(),
                balance = self.balance.to_string(),
                last_settled = self.last_settled.as_secs(),
                "JOB_REVISE_RATE_FINALIZED",
            );

            return JobResult::Success;
        } else if log.topics()[0] == METADATA_UPDATED {
            // IMPORTANT: Tuples have to be decoded using abi_decode_sequence
            // if this is changed in the future
            let Ok(metadata) = String::abi_decode(&log.data().data, true).inspect_err(
                |err| error!(?err, data = ?log.data(), "METADATA_UPDATED: Decode failure"),
            ) else {
                return JobResult::Internal;
            };

            info!(metadata, "METADATA_UPDATED");

            let Ok(v) = serde_json::from_str::<Value>(&metadata)
                .inspect_err(|err| error!(?err, "Error reading metadata"))
            else {
                return JobResult::Failed;
            };

            let Some(t) = v["instance"].as_str() else {
                error!("Instance type not set");
                return JobResult::Failed;
            };
            if self.instance_type != t {
                error!("Instance type change not allowed");
                return JobResult::Failed;
            }

            let Some(t) = v["region"].as_str() else {
                error!("Job region not set");
                return JobResult::Failed;
            };
            if self.region != t {
                error!("Region change not allowed");
                return JobResult::Failed;
            }

            let Some(t) = v["memory"].as_i64() else {
                error!("Memory not set");
                return JobResult::Failed;
            };
            if self.req_mem != t {
                error!("Memory change not allowed");
                return JobResult::Failed;
            }

            let Some(t) = v["vcpu"].as_i64() else {
                error!("vcpu not set");
                return JobResult::Failed;
            };
            if self.req_vcpus != t.try_into().unwrap_or(2) {
                error!("vcpu change not allowed");
                return JobResult::Failed;
            }

            let family = v["family"].as_str();
            if family.is_some() && self.family != family.unwrap() {
                error!("Family change not allowed");
                return JobResult::Failed;
            }

            let debug = v["debug"].as_bool().unwrap_or(false);
            self.debug = debug;

            let Some(url) = v["url"].as_str() else {
                error!("EIF url not found! Exiting job");
                return JobResult::Failed;
            };

            self.eif_url = url.to_string();

            let Ok(init_params) = BASE64_STANDARD.decode(v["init_params"].as_str().unwrap_or(""))
            else {
                error!("failed to decode init params");
                return JobResult::Failed;
            };
            self.init_params = init_params.into_boxed_slice();

            // schedule change immediately if not already scheduled
            if !self.infra_change_scheduled {
                self.schedule_launch(0);
            }

            return JobResult::Success;
        } else {
            error!(topic = ?log.topics()[0], "Unknown event");
            return JobResult::Failed;
        }
    }
}

// Registry to track terminated jobs
#[derive(Clone)]
pub struct JobRegistry {
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
            terminated_jobs: Arc::new(Mutex::new(terminated_jobs)),
            save_path,
        })
    }

    fn add_terminated_job(&self, job_id: String) {
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
    // error, likely internal bug, exit but do not terminate instance
    Internal,
}

// manage the complete lifecycle of a job
// returns true if "done"
async fn job_manager_once(
    context: impl SystemContext + Send + Sync,
    mut job_stream: impl StreamExt<Item = Log> + Unpin,
    mut infra_provider: impl InfraProvider + Send + Sync,
    job_id: JobId,
    allowed_regions: &[String],
    aws_delay_duration: u64,
    rates: &[RegionalRates],
    gb_rates: &[GBRateCard],
    address_whitelist: &[String],
    address_blacklist: &[String],
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
            log = job_stream.next(), if job_result == JobResult::Success => {
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
                    Retry => break 'event,
                    // terminate
                    Failed => {
                        state.schedule_termination(0);
                    },
                    // break
                    Internal => break 'event,
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

    job_result
}

async fn job_logs(
    client: &impl Provider<PubSubFrontend>,
    contract: Address,
    job: B256,
) -> Result<impl StreamExt<Item = Log> + Send + '_> {
    let event_filter = Filter::new()
        .address(contract)
        .event_signature(vec![
            keccak256("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)"),
            keccak256("JobSettled(bytes32,uint256,uint256)"),
            keccak256("JobClosed(bytes32)"),
            keccak256("JobDeposited(bytes32,address,uint256)"),
            keccak256("JobWithdrew(bytes32,address,uint256)"),
            keccak256("JobReviseRateInitiated(bytes32,uint256)"),
            keccak256("JobReviseRateCancelled(bytes32)"),
            keccak256("JobReviseRateFinalized(bytes32,uint256)"),
            keccak256("JobMetadataUpdated(bytes32,string)"),
        ])
        .topic1(job);

    // ordering is important to prevent race conditions while getting all logs but
    // it still relies on the RPC being consistent between registering the subscription
    // and querying the cutoff block number

    // register subscription
    let stream = client
        .subscribe_logs(&event_filter.clone().select(0..))
        .await
        .context("failed to subscribe to job logs")?
        .into_stream();

    // get cutoff block number
    let cutoff = client
        .get_block_number()
        .await
        .context("failed to get cutoff block")?;

    // cut off stream at cutoff block
    let stream = stream.filter_map(move |item| {
        if item.block_number.unwrap() > cutoff {
            Some(item)
        } else {
            None
        }
    });

    // get logs up to cutoff
    let old_logs = client
        .get_logs(&event_filter.select(0..=cutoff))
        .await
        .context("failed to query old logs")?;

    // convert to a stream, extract data from items
    let old_logs = tokio_stream::iter(old_logs);

    // stream
    let stream = old_logs.chain(stream);

    Ok(stream)
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  TESTS
// --------------------------------------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloy::hex::{FromHex, ToHexExt};
    use alloy::primitives::{Bytes, B256, U256};
    use alloy::rpc::types::eth::Log;
    use alloy::sol_types::SolValue;
    use tokio::time::{sleep, Duration, Instant};
    use tokio_stream::StreamExt;

    use crate::market;
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
        logs: Vec<(u64, Action, Vec<u8>)>,
        job_manager_params: JobManagerParams,
        test_results: TestResults,
    ) {
        let context = TestSystemContext { start: start_time };

        let job_num = B256::from_hex(&job_manager_params.job_id.id).unwrap();
        let job_logs: Vec<(u64, Log)> = logs
            .into_iter()
            .map(|x| (x.0, test::get_log(x.1, Bytes::from(x.2), job_num)))
            .collect();

        // pending stream appended so job stream never ends
        let job_stream = std::pin::pin!(tokio_stream::iter(job_logs.into_iter())
            .then(|(moment, log)| async move {
                let delay = start_time + Duration::from_secs(moment) - Instant::now();
                sleep(delay).await;
                log
            })
            .chain(tokio_stream::pending()));

        let mut aws: TestAws = Default::default();
        let res = market::job_manager_once(
            context,
            job_stream,
            &mut aws,
            job_manager_params.job_id,
            &job_manager_params.allowed_regions,
            300,
            &test::get_rates(),
            &test::get_gb_rates(),
            &job_manager_params.address_whitelist,
            &job_manager_params.address_blacklist,
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (301, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (301, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (301, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"family\":\"tuna\"}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (301, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (40, Action::Deposit, 500.abi_encode()),
            (60, Action::Withdraw, 500.abi_encode()),
            (100, Action::Settle, (2, 6).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (50, Action::ReviseRateInitiated, 32000000000000u64.abi_encode()),
            (100, Action::ReviseRateFinalized, 32000000000000u64.abi_encode()),
            (150, Action::ReviseRateInitiated, 60000000000000u64.abi_encode()),
            (200, Action::ReviseRateCancelled, [].into()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-east-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),29000000000000u64,31000u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,0u64,0).abi_encode_sequence()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (350, Action::Withdraw, 30000u64.abi_encode()),
            (500, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (350, Action::ReviseRateInitiated, 29000000000000u64.abi_encode()),
            (400, Action::ReviseRateFinalized, 29000000000000u64.abi_encode()),
            (450, Action::ReviseRateInitiated, 31000000000000u64.abi_encode()),
            (500, Action::ReviseRateFinalized, 31000000000000u64.abi_encode()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (500, Action::Close, [].into()),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("owner").encode_hex_with_prefix()],
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (500, Action::Close, [].into()),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("notowner").encode_hex_with_prefix()],
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (500, Action::Close, [].into()),
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
            address_blacklist: vec![compute_address_word("owner").encode_hex_with_prefix()],
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (500, Action::Close, [].into()),
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
            address_blacklist: vec![compute_address_word("notowner").encode_hex_with_prefix()],
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
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_whitelisted() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![
            compute_address_word("owner").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_whitelisted() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![
            compute_address_word("notownereither").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];
        let address_blacklist = vec![];

        // real owner of the job is compute_address_word("owner")

        assert!(!market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_blacklisted() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("owner").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_blacklisted() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("notownereither").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_neither() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![
            compute_address_word("notownereither").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];
        let address_blacklist = vec![
            compute_address_word("definitelynotownereither").encode_hex_with_prefix(),
            compute_address_word("definitelynotowner").encode_hex_with_prefix(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market::whitelist_blacklist_check(
            log.clone(),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_both() {
        let log = test::get_log(Action::Open,
            Bytes::from(("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            B256::ZERO);
        let address_whitelist = vec![
            compute_address_word("owner").encode_hex_with_prefix(),
            compute_address_word("notowner").encode_hex_with_prefix(),
        ];
        let address_blacklist = vec![
            compute_address_word("owner").encode_hex_with_prefix(),
            compute_address_word("definitelynotowner").encode_hex_with_prefix(),
        ];

        // real owner of the job is compute_address_word("owner")

        assert!(!market::whitelist_blacklist_check(
            log.clone(),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (100, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    debug: false,
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (100, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            // instance type has also been updated in the metadata. should fail this job.
            (100, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (100, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (100, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (400, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    debug: false,
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
    async fn test_debug_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = format!("{:064x}", 1);

        let logs = vec![
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (400, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            // init params have also been updated in the metadata. should fail this job.
            (400, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (400, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
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
            (0, Action::Open, ("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0).abi_encode_sequence()),
            (400, Action::MetadataUpdated, "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string().abi_encode()),
            (505, Action::Close, [].into()),
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
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
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
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }
}
