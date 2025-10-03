use std::{future::Future, time::Duration};

use alloy::primitives::U256;
use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::Instant;
use tracing::{error, info};

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

// IMPORTANT: do not import SystemTime, use a SystemContext

// Trait to encapsulate behaviour that should be simulated in tests
pub trait SystemContext {
    fn now_timestamp(&self) -> Duration;
}

pub struct RealSystemContext {}

impl SystemContext for RealSystemContext {
    fn now_timestamp(&self) -> Duration {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
    }
}

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

pub fn whitelist_blacklist_check(
    owner: String,
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

#[derive(PartialEq, Debug)]
pub enum JobResult {
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

#[derive(Debug, Clone)]
pub enum JobEvent {
    Opened {
        job_id: String,
        owner: String,
        provider: String,
        metadata: String,
        rate: U256,
        balance: U256,
        timestamp: U256,
    },
    Closed {
        job_id: String,
    },
    Deposited {
        job_id: String,
        from: String,
        amount: U256,
    },
    Withdrew {
        job_id: String,
        to: String,
        amount: U256,
    },
    Settled {
        job_id: String,
        amount: U256,
        settled_until_ms: U256,
    },
    ReviseRateInitiated {
        job_id: String,
        new_rate: U256,
    },
    ReviseRateCancelled {
        job_id: String,
    },
    ReviseRateFinalized {
        job_id: String,
        new_rate: U256,
    },
    MetadataUpdated {
        job_id: String,
        metadata: String,
    },
}

pub struct JobState<'a> {
    // NOTE: not sure if dyn is a good idea, revisit later
    pub context: &'a (dyn SystemContext + Send + Sync),

    pub job_id: JobId,
    pub launch_delay: u64,
    pub allowed_regions: &'a [String],

    pub balance: U256,
    pub last_settled: Duration,
    pub rate: U256,
    pub original_rate: U256,
    pub family: String,
    pub min_rate: U256,
    pub bandwidth: u64,
    pub eif_url: String,
    pub instance_type: String,
    pub region: String,
    pub req_vcpus: i32,
    pub req_mem: i64,
    pub debug: bool,
    pub init_params: Box<[u8]>,

    // whether instance should exist or not
    pub infra_state: bool,
    // how long to wait for infra change
    pub infra_change_time: Instant,
    // whether to schedule change
    pub infra_change_scheduled: bool,
}

impl<'a> JobState<'a> {
    pub fn new(
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

    pub fn insolvency_duration(&self) -> Duration {
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

    pub async fn heartbeat_check(&mut self, mut infra_provider: impl InfraProvider) {
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

    pub fn handle_insolvency(&mut self) {
        info!("INSOLVENCY");
        self.schedule_termination(0);
    }

    pub fn schedule_launch(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = true;
        info!("Instance launch scheduled");
    }

    pub fn schedule_termination(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = false;
        info!("Instance termination scheduled");
    }

    // exists to implement rescheduling of infra changes on errors
    pub async fn change_infra(&mut self, infra_provider: impl InfraProvider) -> bool {
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

        let family = metadata_json["family"].as_str();
        if update && family.is_some() && self.family != family.unwrap() {
            return Err(anyhow!("Family change not allowed"));
        } else if family.is_some() {
            self.family = family.unwrap().to_owned();
            info!(self.family, "Family");
        }

        let debug = metadata_json["debug"].as_bool().unwrap_or(false);
        self.debug = debug;

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

    // return
    // JobResult::Success on successful processing of a log
    // JobResult::Done on successful processing of a log which ends a job
    // JobResult::Retry on recoverable errors, usually networking
    // JobResult::Failed on unrecoverable errors
    // JobResult::Internal on internal errors, usually bugs
    pub fn process_event(
        &mut self,
        event: JobEvent,
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
            JobEvent::Opened {
                job_id,
                owner,
                provider: _,
                metadata,
                rate,
                balance,
                timestamp,
            } => {
                info!(
                    id = job_id,
                    metadata,
                    rate = rate.to_string(),
                    balance = balance.to_string(),
                    timestamp = timestamp.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "OPENED",
                );

                // update solvency metrics
                self.balance = balance;
                self.rate = rate;
                self.original_rate = rate;
                self.last_settled = Duration::from_secs(timestamp.saturating_to::<u64>());

                if let Err(err) = self.decode_metadata(metadata, false) {
                    error!(id = job_id, ?err);
                    return JobResult::Failed;
                }

                if !self.allowed_regions.contains(&self.region) {
                    error!(
                        id = job_id,
                        self.region, "Region not supported, exiting job"
                    );
                    return JobResult::Failed;
                }

                // blacklist whitelist check
                let allowed =
                    whitelist_blacklist_check(owner, address_whitelist, address_blacklist);
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
                        id = job_id,
                        self.instance_type, "Instance type not supported",
                    );
                    return JobResult::Failed;
                }

                info!(
                    id = job_id,
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
            JobEvent::Settled {
                job_id,
                amount,
                settled_until_ms,
            } => {
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );
                // update solvency metrics
                self.balance -= amount;
                self.last_settled = Duration::from_secs(settled_until_ms.saturating_to::<u64>());
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );

                return JobResult::Success;
            }
            JobEvent::Closed { job_id: _ } => {
                return JobResult::Done;
            }
            JobEvent::Deposited {
                job_id,
                from: _,
                amount,
            } => {
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );
                // update solvency metrics
                self.balance += amount;
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );

                return JobResult::Success;
            }
            JobEvent::Withdrew {
                job_id,
                to: _,
                amount,
            } => {
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );
                // update solvency metrics
                self.balance -= amount;
                info!(
                    id = job_id,
                    amount = amount.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );

                return JobResult::Success;
            }
            JobEvent::ReviseRateInitiated { job_id, new_rate } => {
                info!(
                    id = job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_INITIATED",
                );
                self.original_rate = self.rate;
                self.rate = new_rate;
                if self.rate < self.min_rate {
                    info!(id = job_id, "Revised job rate below min rate, shut down");
                    return JobResult::Done;
                }
                info!(
                    id = job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_INITIATED",
                );

                return JobResult::Success;
            }
            JobEvent::ReviseRateCancelled { job_id } => {
                info!(
                    id = job_id,
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_CANCELLED",
                );
                self.rate = self.original_rate;
                info!(
                    id = job_id,
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_CANCELLED",
                );

                return JobResult::Success;
            }
            JobEvent::ReviseRateFinalized { job_id, new_rate } => {
                info!(
                    id = job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_FINALIZED",
                );
                if self.rate != new_rate {
                    error!(
                        id = job_id,
                        "Something went wrong, finalized rate not same as initiated rate"
                    );
                    return JobResult::Internal;
                }
                self.original_rate = new_rate;
                info!(
                    id = job_id,
                    self.original_rate = self.original_rate.to_string(),
                    rate = self.rate.to_string(),
                    balance = self.balance.to_string(),
                    last_settled = self.last_settled.as_secs(),
                    "JOB_REVISE_RATE_FINALIZED",
                );

                return JobResult::Success;
            }
            JobEvent::MetadataUpdated { job_id, metadata } => {
                info!(id = job_id, metadata, "METADATA_UPDATED");

                if let Err(err) = self.decode_metadata(metadata, true) {
                    error!(id = job_id, ?err);
                    return JobResult::Failed;
                }

                // schedule change immediately if not already scheduled
                if !self.infra_change_scheduled {
                    self.schedule_launch(0);
                }

                return JobResult::Success;
            }
        }
    }
}
