use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};
use std::str::FromStr;

use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, LogData, B256, U256};
use alloy::providers::Provider;
use alloy::pubsub::PubSubFrontend;
use alloy::rpc::types::eth::Log;
use anyhow::{anyhow, Result};
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt;

use crate::market::{GBRateCard, InfraProvider, JobId, LogsProvider, RateCard, RegionalRates};

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub struct SpinUpOutcome {
    pub time: Instant,
    pub job: String,
    pub instance_type: String,
    pub family: String,
    pub region: String,
    pub req_mem: i64,
    pub req_vcpu: i32,
    pub bandwidth: u64,
    pub image_url: String,
    pub debug: bool,
    pub init_params: Box<[u8]>,
    pub contract_address: String,
    pub chain_id: String,
    pub instance_id: String,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub struct SpinDownOutcome {
    pub time: Instant,
    pub job: String,
    pub region: String,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub enum TestAwsOutcome {
    SpinUp(SpinUpOutcome),
    SpinDown(SpinDownOutcome),
}

pub fn compute_instance_id(counter: u64) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write_u8(0);
    hasher.write_u64(counter);

    let hash = hasher.finish();

    format!("{:x}", hash)
}

pub fn compute_instance_ip(counter: u64) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write_u8(1);
    hasher.write_u64(counter);

    let hash = hasher.finish();

    hash.to_le_bytes()
        .iter()
        .map(|x| x.to_string())
        .reduce(|a, b| a + "." + &b)
        .unwrap()
}

pub fn compute_address_word(salt: &str) -> FixedBytes<32> {
    let mut hasher = DefaultHasher::new();
    hasher.write_u8(2);
    hasher.write(salt.as_bytes());

    let hash = hasher.finish();

    FixedBytes::<32>::from_slice(hash.to_le_bytes().repeat(4).as_slice())
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct InstanceMetadata {
    pub instance_id: String,
    pub ip_address: String,
}

#[cfg(test)]
impl InstanceMetadata {
    pub async fn new(counter: u64) -> Self {
        let instance_id = compute_instance_id(counter);
        let ip_address = compute_instance_ip(counter);

        Self {
            instance_id,
            ip_address,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct TestAws {
    pub outcomes: Vec<TestAwsOutcome>,

    // HashMap format - (Job, InstanceMetadata)
    pub instances: HashMap<String, InstanceMetadata>,

    counter: u64,
}

#[cfg(test)]
impl InfraProvider for TestAws {
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
        let res = self.instances.get_key_value(&job.id);
        if let Some(x) = res {
            self.outcomes.push(TestAwsOutcome::SpinUp(SpinUpOutcome {
                time: Instant::now(),
                job: job.id.clone(),
                instance_type: instance_type.to_owned(),
                family: family.to_owned(),
                region: region.to_owned(),
                req_mem,
                req_vcpu,
                bandwidth,
                image_url: image_url.to_owned(),
                debug,
                init_params: init_params.into(),
                contract_address: job.contract.clone(),
                chain_id: job.chain.clone(),
                instance_id: x.1.instance_id.clone(),
            }));

            return Ok(());
        }

        let instance_metadata: InstanceMetadata = InstanceMetadata::new(self.counter).await;
        self.counter += 1;

        self.instances
            .insert(job.id.clone(), instance_metadata.clone());

        self.outcomes.push(TestAwsOutcome::SpinUp(SpinUpOutcome {
            time: Instant::now(),
            job: job.id.clone(),
            instance_type: instance_type.to_owned(),
            family: family.to_owned(),
            region: region.to_owned(),
            req_mem,
            req_vcpu,
            bandwidth,
            image_url: image_url.to_owned(),
            debug,
            init_params: init_params.into(),
            contract_address: job.contract.clone(),
            chain_id: job.chain.clone(),
            instance_id: instance_metadata.instance_id.clone(),
        }));

        Ok(())
    }

    async fn spin_down(&mut self, job: &JobId, region: &str) -> Result<()> {
        self.outcomes
            .push(TestAwsOutcome::SpinDown(SpinDownOutcome {
                time: Instant::now(),
                job: job.id.clone(),
                region: region.to_owned(),
            }));

        self.instances.remove(&job.id);

        Ok(())
    }

    async fn get_job_ip(&self, job: &JobId, _region: &str) -> Result<String> {
        let instance_metadata = self.instances.get(&job.id);
        instance_metadata
            .map(|x| x.ip_address.clone())
            .ok_or(anyhow!("Instance not found for job - {}", job.id))
    }

    async fn check_enclave_running(&mut self, _job: &JobId, _region: &str) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestLogger {}

#[cfg(test)]
impl LogsProvider for TestLogger {
    async fn new_jobs<'a>(
        &'a self,
        _client: &'a impl Provider<PubSubFrontend>,
    ) -> Result<impl StreamExt<Item = (B256, bool)> + 'a> {
        let logs: Vec<Log> = Vec::new();
        Ok(tokio_stream::iter(
            logs.iter()
                .map(|job| (job.topics()[1], false))
                .collect::<Vec<_>>(),
        )
        .throttle(Duration::from_secs(2)))
    }

    async fn job_logs<'a>(
        &'a self,
        _client: &'a impl Provider<PubSubFrontend>,
        job: B256,
    ) -> Result<impl StreamExt<Item = Log> + Send + 'a> {
        let logs: Vec<Log> = Vec::new();
        Ok(tokio_stream::iter(
            logs.into_iter()
                .filter(|log| log.topics()[1] == job)
                .collect::<Vec<_>>(),
        )
        .throttle(Duration::from_secs(2)))
    }
}

#[cfg(test)]
#[derive(Clone)]
pub enum Action {
    Open,
    Close,
    Settle,
    Deposit,
    Withdraw,
    ReviseRateInitiated,
    ReviseRateCancelled,
    ReviseRateFinalized,
    MetadataUpdated,
}

#[cfg(test)]
pub fn get_rates() -> Vec<RegionalRates> {
    vec![RegionalRates {
        region: "ap-south-1".to_owned(),
        rate_cards: vec![RateCard {
            instance: "c6a.xlarge".to_owned(),
            min_rate: U256::from_str_radix("29997916666666", 10).unwrap(),
            cpu: 4,
            memory: 8,
            arch: String::from("amd64"),
        }],
    }]
}

#[cfg(test)]
pub fn get_gb_rates() -> Vec<GBRateCard> {
    vec![GBRateCard {
        region: "Asia South (Mumbai)".to_owned(),
        region_code: "ap-south-1".to_owned(),
        rate: U256::from_str_radix("109300000000000000", 10).unwrap(),
    }]
}

#[cfg(test)]
pub fn get_log(topic: Action, data: Bytes, idx: B256) -> Log {
    let mut log = Log {
        inner: alloy::primitives::Log {
            address: Address::from_str("0x000000000000000000000000000000000000dead").unwrap(),
            data: LogData::new_unchecked(vec![], Bytes::new()),
        },
        ..Default::default()
    };
    match topic {
        Action::Open => {
            log.inner.data = LogData::new_unchecked(
                vec![
                    keccak256("JobOpened(bytes32,string,address,address,uint256,uint256,uint256)"),
                    idx,
                    compute_address_word("owner"),
                    compute_address_word("provider"),
                ],
                data,
            );
        }
        Action::Close => {
            log.inner.data =
                LogData::new_unchecked(vec![keccak256("JobClosed(bytes32)"), idx], data);
        }
        Action::Settle => {
            log.inner.data = LogData::new_unchecked(
                vec![keccak256("JobSettled(bytes32,uint256,uint256)"), idx],
                data,
            );
        }
        Action::Deposit => {
            log.inner.data = LogData::new_unchecked(
                vec![
                    keccak256("JobDeposited(bytes32,address,uint256)"),
                    idx,
                    compute_address_word("depositor"),
                ],
                data,
            );
        }
        Action::Withdraw => {
            log.inner.data = LogData::new_unchecked(
                vec![
                    keccak256("JobWithdrew(bytes32,address,uint256)"),
                    idx,
                    compute_address_word("withdrawer"),
                ],
                data,
            );
        }
        Action::ReviseRateInitiated => {
            log.inner.data = LogData::new_unchecked(
                vec![keccak256("JobReviseRateInitiated(bytes32,uint256)"), idx],
                data,
            );
        }
        Action::ReviseRateCancelled => {
            log.inner.data = LogData::new_unchecked(
                vec![keccak256("JobReviseRateCancelled(bytes32)"), idx],
                data,
            );
        }
        Action::ReviseRateFinalized => {
            log.inner.data = LogData::new_unchecked(
                vec![keccak256("JobReviseRateFinalized(bytes32,uint256)"), idx],
                data,
            );
        }
        Action::MetadataUpdated => {
            log.inner.data = LogData::new_unchecked(
                vec![keccak256("JobMetadataUpdated(bytes32,string)"), idx],
                data,
            );
        }
    }

    log
}
