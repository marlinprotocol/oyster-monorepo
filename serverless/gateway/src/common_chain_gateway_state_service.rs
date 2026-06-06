use alloy::eips::BlockId;
use alloy::primitives::{keccak256, Address, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::Url;
use alloy::transports::http::{Client, Http};
use anyhow::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::Sender;
use tokio::time::{self, sleep, Duration, Instant};
use tracing::{error, info};

use crate::chain_util::get_block_number_by_timestamp;
use crate::constant::{
    COMMON_CHAIN_GATEWAY_CHAIN_ADDED_EVENT, COMMON_CHAIN_GATEWAY_CHAIN_REMOVED_EVENT,
    COMMON_CHAIN_GATEWAY_DEREGISTERED_EVENT, COMMON_CHAIN_GATEWAY_REGISTERED_EVENT,
    GATEWAY_BLOCK_STATES_TO_MAINTAIN, MAX_RETRY_ON_PROVIDER_ERROR, WAIT_BEFORE_HTTP_RPC_CALL,
};
use crate::contract_abi::GatewaysContract::{self, GatewaysContractInstance};
use crate::model::{ContractsClient, GatewayData, Job};

// Initialize the gateway epoch state
pub async fn gateway_epoch_state_service(
    current_time: u64,
    common_chain_rpc_http_url: String,
    contracts_client: Arc<ContractsClient>,
    tx: Sender<Job>,
) {
    let provider: RootProvider<Http<Client>> =
        ProviderBuilder::new().on_http(Url::parse(&common_chain_rpc_http_url).unwrap());
    let provider = Arc::new(provider);

    let current_cycle = (current_time - contracts_client.epoch) / contracts_client.time_interval;
    let initial_epoch_cycle: u64;
    let mut cycle_number: u64;
    if current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN {
        initial_epoch_cycle = current_cycle - GATEWAY_BLOCK_STATES_TO_MAINTAIN + 1;
    } else {
        initial_epoch_cycle = 1;
    };

    let common_chain_gateways_contract = Arc::new(GatewaysContract::new(
        contracts_client.gateways_contract_address,
        provider.clone(),
    ));

    {
        let contract_address_clone = contracts_client.gateways_contract_address;
        let provider_clone = provider.clone();
        let com_chain_gateway_contract_clone = Arc::clone(&common_chain_gateways_contract);
        let gateway_epoch_state_clone = Arc::clone(&contracts_client.gateway_epoch_state);

        cycle_number = initial_epoch_cycle;
        while cycle_number <= current_cycle {
            let _current_cycle = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                - contracts_client.epoch)
                / contracts_client.time_interval;

            if _current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN + cycle_number {
                cycle_number = _current_cycle - GATEWAY_BLOCK_STATES_TO_MAINTAIN + 1;
            }

            let success = generate_gateway_epoch_state_for_cycle(
                contract_address_clone,
                &provider_clone,
                com_chain_gateway_contract_clone.clone(),
                &gateway_epoch_state_clone,
                cycle_number,
                contracts_client.epoch,
                contracts_client.time_interval,
            )
            .await;

            if success.is_err() {
                error!(
                    "Failed to generate gateway epoch state for cycle {} - Error: {:?}",
                    cycle_number, success
                );
                continue;
            }

            callback_for_gateway_epoch_waitlist(contracts_client.clone(), cycle_number, tx.clone())
                .await;

            cycle_number += 1;
        }
    }

    let next_cycle_timestamp: i64 =
        (contracts_client.epoch + ((current_cycle + 1) * contracts_client.time_interval)) as i64;
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;

    let interval_start_instant = if next_cycle_timestamp > current_time {
        Instant::now() + Duration::from_secs((next_cycle_timestamp - current_time) as u64)
    } else {
        Instant::now() - Duration::from_secs((current_time - next_cycle_timestamp) as u64)
    };

    let mut interval = time::interval_at(
        interval_start_instant,
        Duration::from_secs(contracts_client.time_interval),
    );

    loop {
        interval.tick().await;

        loop {
            let current_cycle = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                - contracts_client.epoch)
                / contracts_client.time_interval;

            if current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN + cycle_number {
                cycle_number = current_cycle - GATEWAY_BLOCK_STATES_TO_MAINTAIN + 1;
            }

            let success = generate_gateway_epoch_state_for_cycle(
                contracts_client.gateways_contract_address,
                &provider.clone(),
                common_chain_gateways_contract.clone(),
                &contracts_client.gateway_epoch_state,
                cycle_number,
                contracts_client.epoch,
                contracts_client.time_interval,
            )
            .await;

            if success.is_err() {
                error!(
                    "Failed to generate gateway epoch state for cycle {} - Error: {:?}",
                    cycle_number,
                    success.err().unwrap()
                );
                continue;
            }

            callback_for_gateway_epoch_waitlist(contracts_client.clone(), cycle_number, tx.clone())
                .await;

            let _current_cycle = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                - contracts_client.epoch)
                / contracts_client.time_interval;

            if cycle_number == _current_cycle {
                break;
            }
            cycle_number += 1;
        }
        prune_old_cycle_states(
            &contracts_client.gateway_epoch_state,
            contracts_client.epoch,
            contracts_client.time_interval,
        )
        .await;

        cycle_number += 1;
    }
}

pub async fn generate_gateway_epoch_state_for_cycle(
    contract_address: Address,
    provider: &RootProvider<Http<Client>>,
    com_chain_gateway_contract: Arc<
        GatewaysContractInstance<Http<Client>, Arc<RootProvider<Http<Client>>>>,
    >,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    cycle_number: u64,
    epoch: u64,
    time_interval: u64,
) -> Result<(), Error> {
    // last added cycle will be the cycle number which is less than the current cycle number
    let mut last_added_cycle: Option<u64> = None;
    let mut added_cycles: Vec<u64>;
    let mut from_block_number: u64 = 0;
    // scope for the read lock
    {
        let gateway_epoch_state_guard = gateway_epoch_state.read().unwrap();
        added_cycles = gateway_epoch_state_guard.keys().cloned().collect();
        added_cycles.sort();
    }
    for cycle in added_cycles.iter().rev() {
        if *cycle < cycle_number {
            last_added_cycle = Some(cycle.clone());

            // get last added cycle's block number
            let gateway_cycle_map = gateway_epoch_state
                .read()
                .unwrap()
                .get(&last_added_cycle.unwrap())
                .unwrap()
                .clone();

            if gateway_cycle_map.is_empty() {
                continue;
            } else {
                from_block_number =
                    gateway_cycle_map.values().next().unwrap().last_block_number + 1;
                break;
            }
        }
    }
    drop(added_cycles);

    let timestamp_to_fetch = epoch + (cycle_number * time_interval);

    // in case of no blocks created in this epoch cycle -
    // to_block_number can be less than from_block_number
    let mut to_block_number = get_block_number_by_timestamp(&provider, timestamp_to_fetch).await;
    if to_block_number.is_none() {
        error!(
            "Failed to get block number for timestamp {}",
            timestamp_to_fetch
        );
        to_block_number = Some(from_block_number);
    }

    let to_block_number = to_block_number.unwrap();

    let mut current_cycle_state_epoch: BTreeMap<Address, GatewayData> = BTreeMap::new();

    if last_added_cycle.is_some() {
        // initialize the gateway epoch state[current_cycle] with the previous cycle state
        // scope for the read lock
        {
            current_cycle_state_epoch = gateway_epoch_state
                .read()
                .unwrap()
                .get(&last_added_cycle.unwrap())
                .unwrap()
                .clone();
        }
    }

    // In case where to_block_number <= from_block_number, return here
    // This will happen in the case when no blocks were created in this epoch cycle,
    // so the state remains the same as the previous state
    if to_block_number <= from_block_number {
        // scope for the write lock
        {
            let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
            gateway_epoch_state_guard.insert(cycle_number, current_cycle_state_epoch);
        }
        info!("Generated gateway epoch state for cycle {}", cycle_number);
        return Ok(()); // no blocks to process
    }

    // update the last block number of the gateway data
    for (_, gateway_data) in current_cycle_state_epoch.iter_mut() {
        gateway_data.last_block_number = to_block_number;
    }

    // events are only used to update the gateway state and req_chain_ids, not the stake amount
    let event_filter = Filter::new()
        .address(contract_address)
        .from_block(from_block_number)
        .to_block(to_block_number)
        .events(vec![
            COMMON_CHAIN_GATEWAY_REGISTERED_EVENT,
            COMMON_CHAIN_GATEWAY_DEREGISTERED_EVENT,
            COMMON_CHAIN_GATEWAY_CHAIN_ADDED_EVENT,
            COMMON_CHAIN_GATEWAY_CHAIN_REMOVED_EVENT,
        ]);

    let logs;
    let time_to_wait =
        Instant::now() + Duration::from_secs(time_interval * GATEWAY_BLOCK_STATES_TO_MAINTAIN);
    loop {
        if Instant::now() > time_to_wait {
            return Err(anyhow::anyhow!(
                "Failed to get logs for the gateway contract"
            ));
        }

        let res = provider.get_logs(&event_filter).await;

        if res.is_err() {
            error!(
                "Failed to get logs for the gateway contract - Error: {:?}",
                res.err().unwrap()
            );
            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
            continue;
        }

        logs = res.unwrap();
        break;
    }

    for log in logs {
        let topics = log.topics();

        if topics[0] == keccak256(COMMON_CHAIN_GATEWAY_REGISTERED_EVENT) {
            process_gateway_registered_event(log, to_block_number, &mut current_cycle_state_epoch)
                .await;
        } else if topics[0] == keccak256(COMMON_CHAIN_GATEWAY_DEREGISTERED_EVENT) {
            process_gateway_deregistered_event(log, &mut current_cycle_state_epoch).await;
        } else if topics[0] == keccak256(COMMON_CHAIN_GATEWAY_CHAIN_ADDED_EVENT) {
            process_chain_added_event(log, &mut current_cycle_state_epoch).await;
        } else if topics[0] == keccak256(COMMON_CHAIN_GATEWAY_CHAIN_REMOVED_EVENT) {
            process_chain_removed_event(log, &mut current_cycle_state_epoch).await;
        }
    }

    // fetch the gateways mapping for the updated stakes.
    let gateway_addresses: Vec<Address> = current_cycle_state_epoch.keys().cloned().collect();

    for address in gateway_addresses {
        for _ in 0..MAX_RETRY_ON_PROVIDER_ERROR {
            let gateways_info;

            let info_result = com_chain_gateway_contract
                .gateways(address)
                .block(BlockId::from(to_block_number))
                .call()
                .await;

            match info_result {
                Ok(info) => {
                    gateways_info = info;
                }
                Err(err) => {
                    error!(
                        "Failed to get gateway info for address {} - Error: {:?}",
                        address, err
                    );
                    sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                    continue;
                }
            }

            let current_cycle_gateway_data = current_cycle_state_epoch.get_mut(&address).unwrap();

            current_cycle_gateway_data.stake_amount = gateways_info.stakeAmount;
            current_cycle_gateway_data.draining = gateways_info.draining;
            break;
        }
    }

    // Write current cycle state to the gateway epoch state
    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        gateway_epoch_state_guard.insert(cycle_number, current_cycle_state_epoch);
    }

    info!("Generated gateway epoch state for cycle {}", cycle_number);
    Ok(())
}

async fn process_gateway_registered_event(
    log: Log,
    to_block_number: u64,
    current_cycle_state_epoch: &mut BTreeMap<Address, GatewayData>,
) {
    let gateway_registered_event_decoded =
        GatewaysContract::GatewayRegistered::decode_log(&log.inner, true);

    if gateway_registered_event_decoded.is_err() {
        error!(
            "Failed to decode gateway registered event {}",
            gateway_registered_event_decoded.err().unwrap()
        );
        return;
    }

    let gateway_registered_event_decoded = gateway_registered_event_decoded.unwrap();

    let log_topics = log.topics();
    let address = Address::from_slice(log_topics[1][12..].try_into().unwrap());

    let mut req_chain_ids = BTreeSet::new();

    for &request_chain_id in gateway_registered_event_decoded.chainIds.iter() {
        req_chain_ids.insert(request_chain_id.to::<u64>());
    }

    current_cycle_state_epoch.insert(
        address,
        GatewayData {
            last_block_number: to_block_number,
            address,
            stake_amount: U256::from(0), // gateways call is used to get the stake amount
            req_chain_ids,
            draining: false,
        },
    );
}

async fn process_gateway_deregistered_event(
    log: Log,
    current_cycle_state_epoch: &mut BTreeMap<Address, GatewayData>,
) {
    let log_topics = log.topics();
    let address = Address::from_slice(log_topics[1][12..].try_into().unwrap());

    current_cycle_state_epoch.remove(&address);
}

async fn process_chain_added_event(
    log: Log,
    current_cycle_state_epoch: &mut BTreeMap<Address, GatewayData>,
) {
    let chain_added_event_decoded = GatewaysContract::ChainAdded::decode_log(&log.inner, true);

    if chain_added_event_decoded.is_err() {
        error!(
            "Failed to decode chain added event {}",
            chain_added_event_decoded.err().unwrap()
        );
        return;
    }

    let chain_added_event_decoded = chain_added_event_decoded.unwrap();

    let log_topics = log.topics();
    let address = Address::from_slice(log_topics[1][12..].try_into().unwrap());

    let chain_id = chain_added_event_decoded.chainId.to::<u64>();

    if let Some(gateway_data) = current_cycle_state_epoch.get_mut(&address) {
        gateway_data.req_chain_ids.insert(chain_id);
    }
}

async fn process_chain_removed_event(
    log: Log,
    current_cycle_state_epoch: &mut BTreeMap<Address, GatewayData>,
) {
    let chain_removed_event_decoded = GatewaysContract::ChainRemoved::decode_log(&log.inner, true);

    if chain_removed_event_decoded.is_err() {
        error!(
            "Failed to decode chain removed event {}",
            chain_removed_event_decoded.err().unwrap()
        );
        return;
    }

    let chain_removed_event_decoded = chain_removed_event_decoded.unwrap();

    let log_topics = log.topics();
    let address = Address::from_slice(log_topics[1][12..].try_into().unwrap());

    let chain_id = chain_removed_event_decoded.chainId.to::<u64>();

    if let Some(gateway_data) = current_cycle_state_epoch.get_mut(&address) {
        gateway_data.req_chain_ids.remove(&chain_id);
    }
}

async fn prune_old_cycle_states(
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    epoch: u64,
    time_interval: u64,
) {
    let current_cycle = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        - epoch)
        / time_interval;
    let mut cycles_to_remove = vec![];

    // scope for the read lock
    {
        let gateway_epoch_state_guard = gateway_epoch_state.read().unwrap();
        for cycle in gateway_epoch_state_guard.keys() {
            // if a state is older than 1.5 times the number of states to maintain, remove it
            // chosen a number larger than the number to maintain because in some cases, of delay,
            // an older state might be used to read and initialize the current state
            if current_cycle >= (GATEWAY_BLOCK_STATES_TO_MAINTAIN * 3 / 2) + cycle {
                cycles_to_remove.push(cycle.clone());
            } else {
                break;
            }
        }
    }
    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        for cycle in &cycles_to_remove {
            gateway_epoch_state_guard.remove(cycle);
        }
    }
}

async fn callback_for_gateway_epoch_waitlist(
    contracts_client: Arc<ContractsClient>,
    cycle_number: u64,
    tx: Sender<Job>,
) {
    let mut waitlist_handle = contracts_client
        .gateway_epoch_state_waitlist
        .write()
        .unwrap();
    if let Some(job_list) = waitlist_handle.remove(&cycle_number) {
        let contracts_client_clone = Arc::clone(&contracts_client);
        tokio::spawn(async move {
            for job in job_list {
                contracts_client_clone
                    .clone()
                    .job_relayed_handler(job, tx.clone())
                    .await;
            }
        });
    }
}
