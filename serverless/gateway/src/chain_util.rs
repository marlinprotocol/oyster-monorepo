use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::pubsub::{PubSubFrontend, SubscriptionStream};
use alloy::rpc::types::{BlockTransactionsKind, Filter, Log};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use alloy::transports::http::reqwest::Url;
use alloy::transports::http::{Client, Http};
use anyhow::Result;
use futures_core::stream::Stream;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use tracing::{error, info};

use crate::constant::{
    MAX_RETRY_ON_PROVIDER_ERROR, MAX_TX_RECEIPT_RETRIES, WAIT_BEFORE_HTTP_RPC_CALL,
};
use crate::error::ServerlessError;
use crate::model::{Job, JobMode, RequestChainData};

pub trait LogsProvider {
    fn common_chain_jobs<'a>(
        &'a self,
        common_chain_ws_client: &'a RootProvider<PubSubFrontend>,
    ) -> impl Future<Output = Result<SubscriptionStream<Log>>>;

    fn req_chain_jobs<'a>(
        &'a self,
        req_chain_ws_client: &'a RootProvider<PubSubFrontend>,
        req_chain_client: &'a RequestChainData,
    ) -> impl Future<Output = Result<impl Stream<Item = Log> + Unpin>>;

    fn gateways_job_relayed_logs<'a, P: HttpProviderLogs>(
        &'a self,
        job: Job,
        common_chain_http_provider: &'a P,
    ) -> impl Future<Output = Result<Vec<Log>>>;

    fn request_chain_historic_subscription_jobs<'a, P: HttpProviderLogs>(
        &'a self,
        req_chain_client: &'a RequestChainData,
        req_chain_http_provider: &'a P,
    ) -> impl Future<Output = Result<Vec<Log>>>;
}

pub trait HttpProviderLogs {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError>;
}

pub struct HttpProvider {
    pub url: String,
}

impl HttpProvider {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl HttpProviderLogs for HttpProvider {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError> {
        let provider: RootProvider<Http<Client>> =
            ProviderBuilder::new().on_http(Url::parse(&self.url).unwrap());
        let logs = provider.get_logs(filter).await.unwrap();
        Ok(logs)
    }
}

pub async fn get_block_number_by_timestamp(
    provider: &RootProvider<Http<Client>>,
    target_timestamp: u64,
) -> Option<u64> {
    let mut block_number: u64 = 0;
    for _ in 0..5 {
        let get_block_number_result = provider.get_block_number().await;

        if get_block_number_result.is_err() {
            error!(
                "Failed to fetch block number. Error: {:#?}",
                get_block_number_result.err()
            );
            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
            continue;
        }

        block_number = get_block_number_result.unwrap();
        break;
    }

    if block_number == 0 {
        error!("Failed to fetch block number");
        return None;
    }

    let mut block_rate_per_second: f64;
    let mut first_block_number = 0;
    let mut first_block_timestamp = 0;
    let mut earliest_block_number_after_target_ts = u64::MAX;

    'less_than_block_number: while block_number > 0 {
        let block = provider
            .get_block(block_number.into(), BlockTransactionsKind::Hashes)
            .await;
        if block.is_err() {
            error!(
                "Failed to fetch block number {}. Error: {:#?}",
                block_number,
                block.err()
            );
            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
            continue;
        }
        let block = block.unwrap();
        if block.is_none() {
            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
            continue;
        }
        let block = block.unwrap();

        // target_timestamp (the end bound of the interval) is excluded from the search
        if block.header.timestamp < target_timestamp {
            if first_block_timestamp == 0 {
                first_block_timestamp = block.header.timestamp;
                first_block_number = block_number;
            }

            // Fetch the next block to confirm this is the latest block with timestamp < target_timestamp
            let next_block_number = block_number + 1;

            let mut retry_on_error = 0;
            'next_block_check: loop {
                let next_block_result = provider
                    .get_block(next_block_number.into(), BlockTransactionsKind::Hashes)
                    .await;

                match next_block_result {
                    Ok(Some(block)) => {
                        // next_block exists
                        if block.header.timestamp >= target_timestamp {
                            // The next block's timestamp is greater than or equal to the target timestamp,
                            // so return the current block number
                            return Some(block_number);
                        }

                        if block.header.timestamp != first_block_timestamp
                            && block.header.timestamp + 1 < target_timestamp
                        {
                            if block.header.timestamp < first_block_timestamp {
                                block_rate_per_second = (first_block_number - next_block_number)
                                    as f64
                                    / (first_block_timestamp - block.header.timestamp) as f64;
                            } else {
                                block_rate_per_second = (next_block_number - first_block_number)
                                    as f64
                                    / (block.header.timestamp - first_block_timestamp) as f64;
                            }
                            info!("Block rate per second: {}", block_rate_per_second);
                            // take ceil of block_rate * time_delta in case of fractional block
                            block_number = block_number
                                + ((target_timestamp - block.header.timestamp) as f64
                                    * block_rate_per_second)
                                    .ceil() as u64;
                        } else {
                            block_number = block_number + 1;
                        }

                        if block_number >= earliest_block_number_after_target_ts {
                            block_number = earliest_block_number_after_target_ts - 1;
                            earliest_block_number_after_target_ts -= 1;
                        }
                        sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                        continue 'less_than_block_number;
                    }
                    Ok(None) => {
                        // The next block does not exist.
                        // Wait for the next block to be created to be sure that
                        // the current block_number is the required block_number
                        sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                        continue 'next_block_check;
                    }
                    Err(err) => {
                        error!(
                            "Failed to fetch block number {}. Err: {}",
                            next_block_number, err
                        );
                        retry_on_error += 1;
                        if retry_on_error <= MAX_RETRY_ON_PROVIDER_ERROR {
                            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                            continue 'next_block_check;
                        }
                        return None;
                    }
                }
            }
        } else {
            if block_number < earliest_block_number_after_target_ts {
                earliest_block_number_after_target_ts = block_number;
            }

            if first_block_timestamp == 0 {
                first_block_timestamp = block.header.timestamp;
                first_block_number = block_number;
            }
            // Calculate the avg block rate per second using the first recorded block timestamp
            if first_block_timestamp > block.header.timestamp + 1 {
                block_rate_per_second = (first_block_number - block_number) as f64
                    / (first_block_timestamp - block.header.timestamp) as f64;
                info!("Block rate per second: {}", block_rate_per_second);

                let block_go_back = ((block.header.timestamp - target_timestamp) as f64
                    * block_rate_per_second) as u64;
                if block_go_back != 0 {
                    if block_number >= block_go_back {
                        block_number = block_number - block_go_back + 1;
                    } else {
                        block_number = 1;
                    }
                }
            }
        }
        block_number -= 1;
    }
    None
}

pub fn sign_relay_job_request(
    signer_key: &SigningKey,
    job_id: U256,
    codehash: &FixedBytes<32>,
    code_inputs: &Bytes,
    user_timeout: U256,
    job_start_time: u64,
    sequence_number: u8,
    job_owner: &Address,
    env: u8,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let relay_job_typehash = keccak256(
            "RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint8 env,uint256 signTimestamp)"
        );

    let code_inputs_hash = keccak256(code_inputs);

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(relay_job_typehash, 32),
        DynSolValue::Uint(job_id, 256),
        DynSolValue::FixedBytes(*codehash, 32),
        DynSolValue::FixedBytes(code_inputs_hash, 32),
        DynSolValue::Uint(user_timeout, 256),
        DynSolValue::Uint(U256::from(job_start_time), 256),
        DynSolValue::Uint(U256::from(sequence_number), 8),
        DynSolValue::Address(*job_owner),
        DynSolValue::Uint(U256::from(env), 8),
        DynSolValue::Uint(U256::from(sign_timestamp), 256),
    ]);

    let hash_struct = keccak256(token_list.abi_encode());

    let gateway_jobs_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.GatewayJobs"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(gateway_jobs_domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    let sig = signer_key.sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        error!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}

pub fn sign_reassign_gateway_relay_request(
    signer_key: &SigningKey,
    job_id: U256,
    gateway_operator_old: &Address,
    job_owner: &Address,
    sequence_number: u8,
    job_start_time: u64,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let reassign_gateway_relay_typehash = keccak256(
            "ReassignGateway(uint256 jobId,address gatewayOld,address jobOwner,uint8 sequenceId,uint256 jobRequestTimestamp,uint256 signTimestamp)"
        );

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(reassign_gateway_relay_typehash, 32),
        DynSolValue::Uint(job_id, 256),
        DynSolValue::Address(*gateway_operator_old),
        DynSolValue::Address(*job_owner),
        DynSolValue::Uint(U256::from(sequence_number), 8),
        DynSolValue::Uint(U256::from(job_start_time), 256),
        DynSolValue::Uint(U256::from(sign_timestamp), 256),
    ]);

    let hash_struct = keccak256(token_list.abi_encode());

    let gateway_jobs_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.GatewayJobs"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(gateway_jobs_domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        error!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}

pub fn sign_job_response_request(
    signer_key: &SigningKey,
    job_id: U256,
    output: Bytes,
    total_time: U256,
    error_code: u8,
    job_mode: JobMode,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let job_response_typehash = keccak256(
        "JobResponse(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)"
    );

    let output_hash = keccak256(output);

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(job_response_typehash, 32),
        DynSolValue::Uint(job_id, 256),
        DynSolValue::FixedBytes(output_hash, 32),
        DynSolValue::Uint(total_time, 256),
        DynSolValue::Uint(U256::from(error_code), 8),
        DynSolValue::Uint(U256::from(sign_timestamp), 256),
    ]);

    let hash_struct = keccak256(token_list.abi_encode());

    let contract_name;
    if job_mode == JobMode::Once {
        contract_name = "marlin.oyster.Relay";
    } else {
        contract_name = "marlin.oyster.RelaySubscriptions";
    }

    let gateway_jobs_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256(contract_name), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(gateway_jobs_domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        error!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}

pub async fn confirm_event(
    mut log: Log,
    http_rpc_url: &String,
    confirmation_blocks: u64,
    last_seen_block: Arc<AtomicU64>,
) -> Log {
    let provider: RootProvider<Http<Client>> =
        ProviderBuilder::new().on_http(Url::parse(http_rpc_url).unwrap());

    let log_transaction_hash = log.transaction_hash.unwrap_or(B256::ZERO);
    // Verify transaction hash is of valid length and not 0
    if log_transaction_hash == B256::ZERO {
        log.removed = true;
        return log;
    }

    let mut retries = 0;
    let mut first_iteration = true;
    loop {
        if last_seen_block.load(Ordering::SeqCst)
            >= log.block_number.unwrap_or(0) + confirmation_blocks
        {
            match provider
                .get_transaction_receipt(log.transaction_hash.unwrap_or(B256::ZERO))
                .await
            {
                Ok(Some(_)) => {
                    info!("Event Confirmed");
                    break;
                }
                Ok(None) => {
                    info!("Event reverted due to re-org");
                    log.removed = true;
                    break;
                }
                Err(err) => {
                    error!("Failed to fetch transaction receipt. Error: {:#?}", err);
                    retries += 1;
                    if retries >= MAX_TX_RECEIPT_RETRIES {
                        error!("Max retries reached. Exiting");
                        log.removed = true;
                        break;
                    }
                    sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                    continue;
                }
            };
        }

        if first_iteration {
            first_iteration = false;
        } else {
            sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
        }

        let curr_block_number = match provider.get_block_number().await {
            Ok(block_number) => block_number,
            Err(err) => {
                error!("Failed to fetch block number. Error: {:#?}", err);
                sleep(Duration::from_millis(WAIT_BEFORE_HTTP_RPC_CALL)).await;
                continue;
            }
        };
        last_seen_block.store(curr_block_number, Ordering::SeqCst);
    }
    log
}
