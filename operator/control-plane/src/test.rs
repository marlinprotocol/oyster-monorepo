use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};

use alloy_primitives::hex::ToHexExt;
#[cfg(test)]
use alloy_primitives::B256;
use alloy_primitives::{FixedBytes, U256};
use anyhow::{anyhow, Result};
#[cfg(test)]
use tokio::time::Instant;

use crate::market::{GBRateCard, InfraProvider, JobId, RateCard, RegionalRates};
#[cfg(test)]
use crate::market::{JobEvent, JobEventName};

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub struct SpinUpOutcome {
    pub time: Instant,
    pub job: String,
    pub instance_type: String,
    pub region: String,
    pub req_mem: i64,
    pub req_vcpu: i32,
    pub bandwidth: u64,
    pub image_url: String,
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

pub fn compute_address_word(salt: &str) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write_u8(2);
    hasher.write(salt.as_bytes());

    let hash = hasher.finish();

    FixedBytes::<32>::from_slice(hash.to_le_bytes().repeat(4).as_slice()).encode_hex_with_prefix()
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
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> Result<()> {
        let res = self.instances.get_key_value(&job.id);
        if let Some(x) = res {
            self.outcomes.push(TestAwsOutcome::SpinUp(SpinUpOutcome {
                time: Instant::now(),
                job: job.id.clone(),
                instance_type: instance_type.to_owned(),
                region: region.to_owned(),
                req_mem,
                req_vcpu,
                bandwidth,
                image_url: image_url.to_owned(),
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
            region: region.to_owned(),
            req_mem,
            req_vcpu,
            bandwidth,
            image_url: image_url.to_owned(),
            init_params: init_params.into(),
            contract_address: job.contract.clone(),
            chain_id: job.chain.clone(),
            instance_id: instance_metadata.instance_id.clone(),
        }));

        Ok(())
    }

    async fn spin_down(&mut self, job: &JobId, region: &str, bandwidth: u64) -> Result<()> {
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
pub enum Action {
    Open(String, u64, u64, i64),
    Close,
    Settle(u64, i64),
    Deposit(u64),
    Withdraw(u64),
    ReviseRateInitiated(u64),
    ReviseRateCancelled,
    ReviseRateFinalized(u64),
    MetadataUpdated(String),
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
pub fn get_event(topic: Action, id: i64, job_idx: B256) -> JobEvent {
    use alloy_primitives::hex::ToHexExt;

    match topic {
        Action::Open(metadata, rate, balance, timestamp) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::Opened,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "owner": compute_address_word("owner"),
                "provider": compute_address_word("provider"),
                "metadata": metadata,
                "rate": rate,
                "balance": balance,
                "timestamp": timestamp,
            }),
        },
        Action::Close => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::Closed,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
            }),
        },
        Action::Settle(amount, timestamp) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::Settled,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "amount": amount,
                "timestamp": timestamp,
            }),
        },
        Action::Deposit(amount) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::Deposited,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "from": compute_address_word("depositor"),
                "amount": amount,
            }),
        },
        Action::Withdraw(amount) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::Withdrew,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "to": compute_address_word("withdrawer"),
                "amount": amount,
            }),
        },
        Action::ReviseRateInitiated(rate) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::ReviseRateInitiated,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "new_rate": rate,
            }),
        },
        Action::ReviseRateCancelled => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::ReviseRateCancelled,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
            }),
        },
        Action::ReviseRateFinalized(rate) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::ReviseRateFinalized,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "new_rate": rate,
            }),
        },
        Action::MetadataUpdated(metadata) => JobEvent {
            id: id,
            job_id: job_idx.encode_hex_with_prefix(),
            event_name: JobEventName::MetadataUpdated,
            event_data: serde_json::json!({
                "job_id": job_idx.encode_hex_with_prefix(),
                "new_metadata": metadata,
            }),
        },
    }
}
