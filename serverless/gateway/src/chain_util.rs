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
use log::{error, info};
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration};

use crate::constant::{
    LOGS_BLOCK_RANGE, LOGS_CHUNK_MAX_ATTEMPTS, LOGS_CHUNK_RETRY_BACKOFF_MS,
    LOGS_CHUNK_RETRY_MAX_BACKOFF_MS, LOGS_CHUNK_TIMEOUT, LOGS_DEDUPE_BLOCK_WINDOW,
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
}

pub trait HttpProviderLogs {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError>;
    async fn get_latest_block_number(&self) -> Result<u64, ServerlessError>;
}

pub struct HttpProvider {
    pub url: String,
}

impl HttpProvider {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    fn provider(&self) -> Result<RootProvider<Http<Client>>, ServerlessError> {
        let url = Url::parse(&self.url)
            .map_err(|err| ServerlessError::LogsFetchFailure(err.to_string()))?;
        Ok(ProviderBuilder::new().on_http(url))
    }
}

impl HttpProviderLogs for HttpProvider {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError> {
        HttpProviderLogs::get_logs(&self.provider()?, filter).await
    }

    async fn get_latest_block_number(&self) -> Result<u64, ServerlessError> {
        HttpProviderLogs::get_latest_block_number(&self.provider()?).await
    }
}

impl HttpProviderLogs for RootProvider<Http<Client>> {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError> {
        Provider::get_logs(self, filter)
            .await
            .map_err(|err| ServerlessError::LogsFetchFailure(err.to_string()))
    }

    async fn get_latest_block_number(&self) -> Result<u64, ServerlessError> {
        Provider::get_block_number(self)
            .await
            .map_err(|err| ServerlessError::BlockNumberFetchFailure(err.to_string()))
    }
}

// Progress of a log query that is split into chunks of LOGS_BLOCK_RANGE blocks.
// It is kept by the caller, so a query that failed on one chunk can be continued
// from that chunk instead of from the first block.
#[derive(Debug)]
pub struct LogsScan {
    pub next_block: u64,
    pub to_block: u64,
    pub logs: Vec<Log>,
}

impl LogsScan {
    pub fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            next_block: from_block,
            to_block,
            logs: Vec::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.next_block > self.to_block
    }
}

// Fetch the logs matching the filter for the blocks left in the scan, one chunk at a time,
// since RPCs limit the block range of a single eth_getLogs query.
// Each chunk has its own timeout and is retried with a backoff. There is no deadline for
// the whole scan. If a chunk keeps failing the error is returned and the scan keeps the
// logs of the completed chunks, calling again with the same scan continues from there.
pub async fn get_logs_in_chunks<P: HttpProviderLogs>(
    provider: &P,
    filter: &Filter,
    scan: &mut LogsScan,
) -> Result<(), ServerlessError> {
    while !scan.is_complete() {
        let chunk_from = scan.next_block;
        let chunk_to = std::cmp::min(
            chunk_from.saturating_add(LOGS_BLOCK_RANGE - 1),
            scan.to_block,
        );
        let chunk_filter = filter.clone().from_block(chunk_from).to_block(chunk_to);

        let mut attempt: u8 = 1;
        let mut backoff = LOGS_CHUNK_RETRY_BACKOFF_MS;
        let chunk_logs = loop {
            let res = timeout(
                Duration::from_secs(LOGS_CHUNK_TIMEOUT),
                provider.get_logs(&chunk_filter),
            )
            .await
            .unwrap_or_else(|_| {
                Err(ServerlessError::LogsFetchFailure(format!(
                    "timed out after {} seconds",
                    LOGS_CHUNK_TIMEOUT
                )))
            });

            match res {
                Ok(chunk_logs) => break chunk_logs,
                Err(err) => {
                    error!(
                        "Failed to get logs for blocks {} to {} (attempt {} of {}) - Error: {}",
                        chunk_from, chunk_to, attempt, LOGS_CHUNK_MAX_ATTEMPTS, err
                    );
                    if attempt >= LOGS_CHUNK_MAX_ATTEMPTS {
                        return Err(err);
                    }
                    attempt += 1;
                    sleep(Duration::from_millis(backoff)).await;
                    backoff = std::cmp::min(backoff * 2, LOGS_CHUNK_RETRY_MAX_BACKOFF_MS);
                }
            }
        };

        scan.logs.extend(chunk_logs);
        scan.next_block = chunk_to + 1;
    }

    Ok(())
}

// Fetch the logs matching the filter from the given block to the latest block, in chunks.
pub async fn get_logs_till_latest_block<P: HttpProviderLogs>(
    provider: &P,
    filter: &Filter,
    from_block: u64,
) -> Result<Vec<Log>, ServerlessError> {
    let latest_block = get_latest_block_number(provider).await?;

    let mut scan = LogsScan::new(from_block, latest_block);
    get_logs_in_chunks(provider, filter, &mut scan).await?;
    Ok(scan.logs)
}

// Call f until it succeeds, with a timeout for each call and a backoff between the calls.
// After LOGS_CHUNK_MAX_ATTEMPTS failed calls the last error is returned.
pub async fn retry_with_backoff<T, F, Fut>(
    description: &str,
    timeout_error: fn(String) -> ServerlessError,
    mut f: F,
) -> Result<T, ServerlessError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ServerlessError>>,
{
    let mut attempt: u8 = 1;
    let mut backoff = LOGS_CHUNK_RETRY_BACKOFF_MS;
    loop {
        let res = timeout(Duration::from_secs(LOGS_CHUNK_TIMEOUT), f())
            .await
            .unwrap_or_else(|_| {
                Err(timeout_error(format!(
                    "timed out after {} seconds",
                    LOGS_CHUNK_TIMEOUT
                )))
            });

        match res {
            Ok(value) => return Ok(value),
            Err(err) => {
                error!(
                    "Failed to {} (attempt {} of {}) - Error: {}",
                    description, attempt, LOGS_CHUNK_MAX_ATTEMPTS, err
                );
                if attempt >= LOGS_CHUNK_MAX_ATTEMPTS {
                    return Err(err);
                }
                attempt += 1;
                sleep(Duration::from_millis(backoff)).await;
                backoff = std::cmp::min(backoff * 2, LOGS_CHUNK_RETRY_MAX_BACKOFF_MS);
            }
        }
    }
}

// Get the latest block number, with a timeout and retries.
pub async fn get_latest_block_number<P: HttpProviderLogs>(
    provider: &P,
) -> Result<u64, ServerlessError> {
    retry_with_backoff(
        "get the latest block number",
        ServerlessError::BlockNumberFetchFailure,
        || provider.get_latest_block_number(),
    )
    .await
}

// Position of an event stream, kept across reconnects of its websocket.
// The logs of all the blocks before next_block have been read with eth_getLogs.
// The websocket subscription delivers new logs only, and it can miss logs without ending:
// the websocket reconnects inside the provider and a lagging receiver drops logs. So the logs
// from next_block on are also read with eth_getLogs regularly (see backfill_logs), and a log
// delivered both ways is processed once, by its (block number, log index).
#[derive(Debug)]
pub struct LogsCursor {
    pub next_block: u64,
    seen: BTreeSet<(u64, u64)>,
}

impl LogsCursor {
    pub fn new(next_block: u64) -> Self {
        Self {
            next_block,
            seen: BTreeSet::new(),
        }
    }

    // Returns true if the log has not been processed before and is to be processed now.
    // Logs of blocks more than LOGS_DEDUPE_BLOCK_WINDOW blocks before next_block have been
    // read with eth_getLogs and are not processed again.
    pub fn accept(&mut self, log: &Log) -> bool {
        let (Some(block_number), Some(log_index)) = (log.block_number, log.log_index) else {
            return true;
        };
        if block_number.saturating_add(LOGS_DEDUPE_BLOCK_WINDOW) < self.next_block {
            return false;
        }
        self.seen.insert((block_number, log_index))
    }

    // The logs of all the blocks before next_block have been read
    pub fn advance(&mut self, next_block: u64) {
        if next_block <= self.next_block {
            return;
        }
        self.next_block = next_block;
        let keep_from = next_block.saturating_sub(LOGS_DEDUPE_BLOCK_WINDOW);
        self.seen = self.seen.split_off(&(keep_from, 0));
    }
}

// Blocks to read with eth_getLogs: from the cursor to the latest block that has the given
// number of confirmations. None if there is nothing to read.
pub fn backfill_range(
    next_block: u64,
    latest_block: u64,
    confirmation_blocks: u64,
) -> Option<(u64, u64)> {
    let to_block = latest_block.checked_sub(confirmation_blocks)?;
    if to_block < next_block {
        return None;
    }
    Some((next_block, to_block))
}

// Read the logs matching the filter from the cursor to the confirmed head with eth_getLogs, in
// chunks, and return the ones that were not processed before, in chain order. The cursor is
// advanced over the chunks that were read, also when a later chunk fails; the blocks left are
// read on the next call.
pub async fn backfill_logs<P: HttpProviderLogs>(
    provider: &P,
    filter: &Filter,
    cursor: &mut LogsCursor,
    confirmation_blocks: u64,
) -> Vec<Log> {
    let latest_block = match get_latest_block_number(provider).await {
        Ok(latest_block) => latest_block,
        Err(err) => {
            error!(
                "Failed to get the latest block number for reading the missed logs - Error: {}",
                err
            );
            return Vec::new();
        }
    };

    let Some((from_block, to_block)) =
        backfill_range(cursor.next_block, latest_block, confirmation_blocks)
    else {
        return Vec::new();
    };

    let mut scan = LogsScan::new(from_block, to_block);
    if let Err(err) = get_logs_in_chunks(provider, filter, &mut scan).await {
        error!(
            "Failed to read the logs of blocks {} to {}, continuing from block {} later - Error: {}",
            from_block, to_block, scan.next_block, err
        );
    }

    let logs = scan
        .logs
        .into_iter()
        .filter(|log| !log.removed && cursor.accept(log))
        .collect();
    cursor.advance(scan.next_block);
    logs
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

#[cfg(test)]
mod chain_util_tests {
    use std::sync::Mutex;

    use super::*;

    // Provider that records the block range of every query and fails the given queries
    struct RangeRecordingProvider {
        queries: Mutex<Vec<(u64, u64)>>,
        failing_queries: Vec<usize>,
    }

    impl RangeRecordingProvider {
        fn new(failing_queries: Vec<usize>) -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
                failing_queries,
            }
        }
    }

    impl HttpProviderLogs for RangeRecordingProvider {
        async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ServerlessError> {
            let from_block = filter.get_from_block().unwrap();
            let to_block = filter.get_to_block().unwrap();
            let query_index = {
                let mut queries = self.queries.lock().unwrap();
                queries.push((from_block, to_block));
                queries.len() - 1
            };
            if self.failing_queries.contains(&query_index) {
                return Err(ServerlessError::LogsFetchFailure("mock failure".to_owned()));
            }
            Ok(vec![Log {
                block_number: Some(from_block),
                log_index: Some(0),
                ..Default::default()
            }])
        }

        async fn get_latest_block_number(&self) -> Result<u64, ServerlessError> {
            Ok(LOGS_BLOCK_RANGE + 100)
        }
    }

    #[tokio::test]
    async fn test_get_logs_till_latest_block_splits_the_range() {
        let provider = RangeRecordingProvider::new(vec![]);

        let logs = get_logs_till_latest_block(&provider, &Filter::new(), 50)
            .await
            .unwrap();

        assert_eq!(
            *provider.queries.lock().unwrap(),
            vec![
                (50, LOGS_BLOCK_RANGE + 49),
                (LOGS_BLOCK_RANGE + 50, LOGS_BLOCK_RANGE + 100),
            ]
        );
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_get_logs_till_latest_block_returns_the_error() {
        // the first chunk fails all its attempts
        let max_attempts = LOGS_CHUNK_MAX_ATTEMPTS as usize;
        let provider = RangeRecordingProvider::new((0..max_attempts).collect());

        let res = get_logs_till_latest_block(&provider, &Filter::new(), 50).await;

        assert_eq!(
            res.unwrap_err(),
            ServerlessError::LogsFetchFailure("mock failure".to_owned())
        );
    }

    #[tokio::test]
    async fn test_get_logs_in_chunks_splits_the_range() {
        let provider = RangeRecordingProvider::new(vec![]);
        let mut scan = LogsScan::new(10, 2 * LOGS_BLOCK_RANGE + 20);

        let res = get_logs_in_chunks(&provider, &Filter::new(), &mut scan).await;

        assert_eq!(res, Ok(()));
        assert!(scan.is_complete());
        assert_eq!(
            *provider.queries.lock().unwrap(),
            vec![
                (10, LOGS_BLOCK_RANGE + 9),
                (LOGS_BLOCK_RANGE + 10, 2 * LOGS_BLOCK_RANGE + 9),
                (2 * LOGS_BLOCK_RANGE + 10, 2 * LOGS_BLOCK_RANGE + 20),
            ]
        );
        assert_eq!(scan.logs.len(), 3);
    }

    #[tokio::test]
    async fn test_get_logs_in_chunks_retries_a_failed_chunk() {
        // the second chunk fails twice and then succeeds
        let provider = RangeRecordingProvider::new(vec![1, 2]);
        let mut scan = LogsScan::new(0, 2 * LOGS_BLOCK_RANGE - 1);

        let res = get_logs_in_chunks(&provider, &Filter::new(), &mut scan).await;

        assert_eq!(res, Ok(()));
        assert_eq!(
            *provider.queries.lock().unwrap(),
            vec![
                (0, LOGS_BLOCK_RANGE - 1),
                (LOGS_BLOCK_RANGE, 2 * LOGS_BLOCK_RANGE - 1),
                (LOGS_BLOCK_RANGE, 2 * LOGS_BLOCK_RANGE - 1),
                (LOGS_BLOCK_RANGE, 2 * LOGS_BLOCK_RANGE - 1),
            ]
        );
        assert_eq!(scan.logs.len(), 2);
    }

    #[tokio::test]
    async fn test_get_logs_in_chunks_resumes_from_the_failed_chunk() {
        // the second chunk fails all its attempts
        let max_attempts = LOGS_CHUNK_MAX_ATTEMPTS as usize;
        let provider = RangeRecordingProvider::new((1..=max_attempts).collect());
        let mut scan = LogsScan::new(0, 3 * LOGS_BLOCK_RANGE - 1);

        let res = get_logs_in_chunks(&provider, &Filter::new(), &mut scan).await;

        assert_eq!(
            res,
            Err(ServerlessError::LogsFetchFailure("mock failure".to_owned()))
        );
        assert!(!scan.is_complete());
        assert_eq!(scan.next_block, LOGS_BLOCK_RANGE);
        assert_eq!(scan.logs.len(), 1);
        assert_eq!(provider.queries.lock().unwrap().len(), 1 + max_attempts);

        // the same scan continues from the second chunk, the first one is not queried again
        let res = get_logs_in_chunks(&provider, &Filter::new(), &mut scan).await;

        assert_eq!(res, Ok(()));
        assert!(scan.is_complete());
        let queries = provider.queries.lock().unwrap();
        assert_eq!(
            queries[1 + max_attempts..],
            [
                (LOGS_BLOCK_RANGE, 2 * LOGS_BLOCK_RANGE - 1),
                (2 * LOGS_BLOCK_RANGE, 3 * LOGS_BLOCK_RANGE - 1),
            ]
        );
        let log_blocks: Vec<u64> = scan
            .logs
            .iter()
            .map(|log| log.block_number.unwrap())
            .collect();
        assert_eq!(log_blocks, vec![0, LOGS_BLOCK_RANGE, 2 * LOGS_BLOCK_RANGE]);
    }

    fn log_at(block_number: u64, log_index: u64) -> Log {
        Log {
            block_number: Some(block_number),
            log_index: Some(log_index),
            ..Default::default()
        }
    }

    #[test]
    fn test_logs_cursor_dedupes_by_block_and_log_index() {
        let mut cursor = LogsCursor::new(100);

        assert!(cursor.accept(&log_at(100, 0)));
        assert!(!cursor.accept(&log_at(100, 0)));
        assert!(cursor.accept(&log_at(100, 1)));
        assert!(cursor.accept(&log_at(101, 0)));
        // a log without position is never treated as a duplicate
        assert!(cursor.accept(&Log::default()));
        assert!(cursor.accept(&Log::default()));

        // logs of blocks already read are still deduplicated inside the window
        cursor.advance(102);
        assert_eq!(cursor.next_block, 102);
        assert!(!cursor.accept(&log_at(100, 1)));
        assert!(cursor.accept(&log_at(100, 2)));

        // the cursor does not move back
        cursor.advance(50);
        assert_eq!(cursor.next_block, 102);

        // logs of blocks before the window have been read with eth_getLogs
        cursor.advance(101 + LOGS_DEDUPE_BLOCK_WINDOW);
        assert!(!cursor.accept(&log_at(100, 3)));
        assert!(cursor.accept(&log_at(101, 1)));
        assert!(!cursor.accept(&log_at(101, 1)));
        // the entries before the window are dropped
        assert!(cursor.seen.iter().all(|(block, _)| *block >= 101));
    }

    #[test]
    fn test_backfill_range() {
        assert_eq!(backfill_range(10, 100, 0), Some((10, 100)));
        assert_eq!(backfill_range(10, 100, 5), Some((10, 95)));
        assert_eq!(backfill_range(95, 100, 5), Some((95, 95)));
        // nothing new with enough confirmations
        assert_eq!(backfill_range(96, 100, 5), None);
        assert_eq!(backfill_range(101, 100, 0), None);
        // chain shorter than the confirmations
        assert_eq!(backfill_range(0, 3, 5), None);
    }

    #[tokio::test]
    async fn test_backfill_logs_reads_from_the_cursor_to_the_confirmed_head() {
        let provider = RangeRecordingProvider::new(vec![]);
        let mut cursor = LogsCursor::new(10);
        // a log of the first block was delivered by the subscription already
        assert!(cursor.accept(&log_at(10, 0)));

        let logs = backfill_logs(&provider, &Filter::new(), &mut cursor, 5).await;

        assert_eq!(
            *provider.queries.lock().unwrap(),
            vec![
                (10, LOGS_BLOCK_RANGE + 9),
                (LOGS_BLOCK_RANGE + 10, LOGS_BLOCK_RANGE + 95),
            ]
        );
        let log_blocks: Vec<u64> = logs.iter().map(|log| log.block_number.unwrap()).collect();
        assert_eq!(log_blocks, vec![LOGS_BLOCK_RANGE + 10]);
        assert_eq!(cursor.next_block, LOGS_BLOCK_RANGE + 96);

        // nothing new to read
        let logs = backfill_logs(&provider, &Filter::new(), &mut cursor, 5).await;
        assert!(logs.is_empty());
        assert_eq!(provider.queries.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_backfill_logs_keeps_the_progress_of_a_failed_backfill() {
        // the second chunk fails all its attempts
        let max_attempts = LOGS_CHUNK_MAX_ATTEMPTS as usize;
        let provider = RangeRecordingProvider::new((1..=max_attempts).collect());
        let mut cursor = LogsCursor::new(10);

        let logs = backfill_logs(&provider, &Filter::new(), &mut cursor, 0).await;

        assert_eq!(logs.len(), 1);
        assert_eq!(cursor.next_block, LOGS_BLOCK_RANGE + 10);

        // the next backfill continues from the failed chunk
        let logs = backfill_logs(&provider, &Filter::new(), &mut cursor, 0).await;
        let log_blocks: Vec<u64> = logs.iter().map(|log| log.block_number.unwrap()).collect();
        assert_eq!(log_blocks, vec![LOGS_BLOCK_RANGE + 10]);
        assert_eq!(cursor.next_block, LOGS_BLOCK_RANGE + 101);
        let queries = provider.queries.lock().unwrap();
        assert_eq!(
            queries[1 + max_attempts..],
            [(LOGS_BLOCK_RANGE + 10, LOGS_BLOCK_RANGE + 100)]
        );
    }
}
