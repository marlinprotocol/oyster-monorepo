use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use actix_web::web::Bytes;
use anyhow::{Context, Result};
use ethers::abi::{Abi, Token};
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::LocalWallet;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tokio::time::sleep;

use crate::cgroups::Cgroups;

// Execution environment ID for the executor image
pub const EXECUTION_ENV_ID: u8 = 1;

pub const HTTP_CALL_RETRY_DELAY: u64 = 10; // Retry interval (in milliseconds) for HTTP requests
pub const GAS_LIMIT_BUFFER: u64 = 200000; // Fixed buffer to add to the estimated gas for setting gas limit
pub const TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20; // Deadline (in secs) for resending pending/dropped execution timeout txns
pub const RESEND_TXN_INTERVAL: u64 = 5; // Interval (in secs) in which to confirm/resend pending/dropped txns
pub const RESEND_GAS_PRICE_INCREMENT_PERCENT: u64 = 10; // Gas price increment percent while resending pending/dropped txns

pub type HttpSignerProvider = SignerMiddleware<Provider<Http>, LocalWallet>;

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the executor configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub workerd_runtime_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub executors_contract_addr: H160,
    pub jobs_contract_addr: H160,
    pub code_contract_addr: String,
    pub enclave_signer_file: String,
    pub execution_buffer_time: u64,
    pub num_selected_executors: u8,
}

// App data struct containing the necessary fields to run the executor
#[derive(Debug)]
pub struct AppState {
    pub cgroups: Mutex<Cgroups>,
    pub job_capacity: usize,
    pub workerd_runtime_path: String,
    pub execution_buffer_time: u64,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub executors_contract_addr: Address,
    pub jobs_contract_addr: Address,
    pub code_contract_addr: String,
    pub num_selected_executors: u8,
    pub enclave_address: H160,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub enclave_registered: AtomicBool,
    pub events_listener_active: Mutex<bool>,
    pub enclave_owner: Mutex<H160>,
    pub http_rpc_client: Mutex<Option<HttpSignerProvider>>,
    pub jobs_contract_abi: Abi,
    pub job_requests_running: Mutex<HashSet<U256>>,
    pub last_block_seen: AtomicU64,
    pub nonce_to_send: Mutex<U256>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImmutableConfig {
    pub owner_address_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MutableConfig {
    pub encrypted_gas_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMutableConfig {
    pub config: MutableConfig,
    pub timestamp: u64,
    pub signature: String
}

#[derive(Debug, Clone, PartialEq)]
pub enum JobsTxnType {
    OUTPUT,
    TIMEOUT,
}

impl JobsTxnType {
    pub fn as_str(&self) -> &str {
        match self {
            JobsTxnType::OUTPUT => "output",
            JobsTxnType::TIMEOUT => "timeout",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct JobOutput {
    pub output: Bytes,
    pub error_code: u8,
    pub total_time: u128,
    pub sign_timestamp: U256,
    pub signature: Bytes,
}

#[derive(Debug, Clone)]
pub struct JobsTxnMetadata {
    pub txn_type: JobsTxnType,
    pub job_id: U256,
    pub job_output: Option<JobOutput>,
    pub retry_deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingTxnData {
    pub txn_hash: H256,
    pub txn_data: JobsTxnMetadata,
    pub http_rpc_client: HttpSignerProvider,
    pub nonce: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub last_monitor_instant: Instant,
}

pub enum JobsTxnSendError {
    NonceTooLow,
    NonceTooHigh,
    OutOfGas,
    GasTooHigh,
    GasPriceLow,
    ContractExecution,
    NetworkConnectivity,
    OtherRetryable,
}

// Returns the 'Jobs' Contract Abi object for encoding transaction data, takes the JSON ABI from 'Jobs.json' file
pub fn load_abi_from_file() -> Result<Abi> {
    let abi_json = include_str!("../Jobs.json");
    let contract: Abi = from_str(&abi_json)
        .context("Failed to deserialize 'Jobs' contract ABI from the Json file Jobs.json")?;

    Ok(contract)
}

// Function to return the 'Jobs' txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    jobs_contract_abi: &Abi,
    jobs_contract_addr: Address,
    job_response: &JobsTxnMetadata,
) -> Result<TypedTransaction> {
    let txn_data = match job_response.txn_type {
        JobsTxnType::OUTPUT => {
            let job_output = job_response.job_output.clone().unwrap();

            // Get the encoding 'Function' object for submitOutput transaction
            let submit_output = jobs_contract_abi.function("submitOutput")?;
            let params = vec![
                Token::Bytes(job_output.signature.into()),
                Token::Uint(job_response.job_id),
                Token::Bytes(job_output.output.into()),
                Token::Uint(job_output.total_time.into()),
                Token::Uint(job_output.error_code.into()),
                Token::Uint(job_output.sign_timestamp),
            ];

            submit_output.encode_input(&params)?
        }
        JobsTxnType::TIMEOUT => {
            // Get the encoding 'Function' object for slashOnExecutionTimeout transaction
            let slash_on_execution_timeout =
                jobs_contract_abi.function("slashOnExecutionTimeout")?;
            let params = vec![Token::Uint(job_response.job_id)];

            slash_on_execution_timeout.encode_input(&params)?
        }
    };

    // Return the TransactionRequest object using the encoded data and 'Jobs' contract address
    Ok(TypedTransaction::Eip1559(Eip1559TransactionRequest {
        to: Some(jobs_contract_addr.into()),
        data: Some(txn_data.into()),
        ..Default::default()
    }))
}

// Function to retrieve the estimated gas required for a txn and the current gas price
// of the network under the retry deadline for the txn, returns `(estimated_gas, gas_price)`
pub async fn estimate_gas_and_price(
    http_rpc_client: HttpSignerProvider,
    txn: &TypedTransaction,
    deadline: Instant,
) -> Option<(U256, U256)> {
    let mut gas_price = U256::zero();

    while Instant::now() < deadline {
        // Request the current gas price for the common chain from the rpc, retry otherwise
        let price = http_rpc_client.get_gas_price().await;
        let Ok(price) = price else {
            eprintln!(
                "Failed to get gas price from the rpc for the network: {:?}",
                price.unwrap_err()
            );

            sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
            continue;
        };

        gas_price = price;
        break;
    }

    if gas_price.is_zero() {
        return None;
    }

    while Instant::now() < deadline {
        // Estimate the gas required for the TransactionRequest from the rpc, retry otherwise
        let estimated_gas = http_rpc_client.estimate_gas(txn, None).await;
        let Ok(estimated_gas) = estimated_gas else {
            let error_string = format!("{:?}", estimated_gas.unwrap_err());
            eprintln!(
                "Failed to estimate gas from the rpc for sending a 'Jobs' transaction: {:?}",
                error_string
            );

            match parse_send_error(error_string.to_lowercase()) {
                // Break in case the contract execution is failing for this txn or the gas required is way high compared to block gas limit
                JobsTxnSendError::GasTooHigh | JobsTxnSendError::ContractExecution => break,
                _ => {
                    sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
                    continue;
                }
            }
        };

        return Some((estimated_gas, gas_price));
    }

    return None;
}

// Function to categorize the rpc send txn errors into relevant enums
// TODO: Add reference to the errors thrown by the rpc while sending a transaction to the network
pub fn parse_send_error(error: String) -> JobsTxnSendError {
    if error.contains("nonce too low") {
        return JobsTxnSendError::NonceTooLow;
    }

    if error.contains("nonce too high") || error.contains("too many pending transactions") {
        return JobsTxnSendError::NonceTooHigh;
    }

    if error.contains("out of gas") {
        return JobsTxnSendError::OutOfGas;
    }

    if error.contains("gas limit too high") || error.contains("transaction exceeds block gas limit")
    {
        return JobsTxnSendError::GasTooHigh;
    }

    if error.contains("gas price too low") || error.contains("transaction underpriced") {
        return JobsTxnSendError::GasPriceLow;
    }

    if error.contains("connection") || error.contains("network") {
        return JobsTxnSendError::NetworkConnectivity;
    }

    if error.contains("reverted") || error.contains("failed") {
        return JobsTxnSendError::ContractExecution;
    }

    return JobsTxnSendError::OtherRetryable;
}
