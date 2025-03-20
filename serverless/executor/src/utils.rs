use std::time::{Duration, Instant};

use anyhow::Result;
use ethers::abi::{Abi, Token};
use ethers::providers::Middleware;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, U256};
use serde_json::Value;
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::constant::HTTP_CALL_RETRY_DELAY;
use crate::model::{HttpSignerProvider, JobsTxnMetadata, JobsTxnSendError, JobsTxnType};

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
    mut gas_estimate_block: Option<u64>,
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

    if gas_estimate_block.is_none() {
        while Instant::now() < deadline {
            let current_block = http_rpc_client.get_block_number().await;
            let Ok(current_block) = current_block else {
                eprintln!("Failed to fetch the latest block number from the rpc for estimating gas of a 'Jobs' transaction: {:?}", current_block.unwrap_err());

                sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
                continue;
            };
            gas_estimate_block = Some(current_block.as_u64());
            break;
        }
    }

    while Instant::now() < deadline {
        // Estimate the gas required for the TransactionRequest from the rpc, retry otherwise
        let estimated_gas = http_rpc_client
            .estimate_gas(txn, gas_estimate_block.map(|block_num| block_num.into()))
            .await;
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

    if error.contains("gas price too low")
        || error.contains("transaction underpriced")
        || error.contains("max fee per gas less than block base fee")
    {
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

pub async fn call_secret_store_endpoint_post(
    port: u16,
    endpoint: &str,
    request_json: Value,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let client = reqwest::Client::new();
    let req_url = "http://127.0.0.1:".to_string() + &port.to_string() + endpoint;

    let response = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            client
                .post(req_url.clone())
                .json(&request_json.clone())
                .send()
                .await
        },
    )
    .await
    .map_err(|err| {
        eprintln!(
            "Failed to send the request to secret store endpoint {}: {:?}",
            endpoint, err
        );
        err
    })?;

    parse_response(response).await
}

pub async fn call_secret_store_endpoint_get(
    port: u16,
    endpoint: &str,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let client = reqwest::Client::new();
    let req_url = "http://127.0.0.1:".to_string() + &port.to_string() + endpoint;

    let response = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async { client.get(req_url.clone()).send().await },
    )
    .await
    .map_err(|err| {
        eprintln!(
            "Failed to send the request to secret store endpoint {}: {:?}",
            endpoint, err
        );
        err
    })?;

    parse_response(response).await
}

async fn parse_response(
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let status_code = response.status();

    let mut response_body = String::new();
    let mut response_json = None;

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        response_json = Some(response.json::<Value>().await.map_err(|err| {
            eprintln!(
                "Failed to parse the response json from the secret store response: {:?}",
                err
            );
            err
        })?);
    } else {
        response_body = response.text().await.map_err(|err| {
            eprintln!(
                "Failed to parse the response body from the secret store response: {:?}",
                err
            );
            err
        })?;
    }

    Ok((status_code, response_body, response_json))
}
