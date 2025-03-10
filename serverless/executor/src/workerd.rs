use std::process::Child;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ethers::abi::{Function, Param, ParamType, StateMutability};
use reqwest::redirect::Policy;
use reqwest::Client;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::cgroups::Cgroups;
use crate::constant::SAVE_CODE_FUNCTION_SELECTOR;

// Define errors that might arise during a job execution
#[derive(Error, Debug)]
pub enum ServerlessError {
    #[error("Failed to retrieve code transaction data")]
    TxDataRetrieve(#[source] reqwest::Error),
    #[error("Tx not found on the desired rpc")]
    TxNotFound,
    #[error("to field of transaction data is not an address")]
    InvalidTxToType,
    #[error("to address {0} does not match expected {1}")]
    InvalidTxToValue(String, String),
    #[error("calldata field of transaction data is not a string")]
    InvalidTxCalldataType,
    #[error("calldata doesn't belong to the expected method")]
    InvalidTxCalldata,
    #[error("calldata field is not a valid hex string")]
    BadCalldata(#[from] hex::FromHexError),
    #[error("Failed to create/write to the code file")]
    CodeFileCreate(#[source] tokio::io::Error),
    #[error("Failed to create/write to the config file")]
    ConfigFileCreate(#[source] tokio::io::Error),
    #[error("Failed to execute cgroups")]
    Execute,
    #[error("Failed to send request to the workerd port")]
    WorkerRequestError(#[source] reqwest::Error),
    #[error("Failed to delete the code file")]
    CodeFileDelete(#[source] tokio::io::Error),
    #[error("Failed to delete the config file")]
    ConfigFileDelete(#[source] tokio::io::Error),
    #[error("Failed to retrieve port number from cgroup")]
    BadPort(#[source] std::num::ParseIntError),
}

pub async fn create_code_file(
    tx_hash: &str,
    slug: &str,
    workerd_runtime_path: &str,
    rpc: &str,
    contract: &str,
) -> Result<(), ServerlessError> {
    // Get code transaction data from its hash
    let mut tx_data = match Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async { get_transaction_data(tx_hash, rpc).await },
    )
    .await
    .map_err(ServerlessError::TxDataRetrieve)?["result"]
        .take()
    {
        Value::Null => Err(ServerlessError::TxNotFound),
        other => Ok(other),
    }?;

    // Get contract address to which the user code transaction is sent
    let contract_address = match tx_data["to"].take() {
        Value::String(value) => Ok(value),
        _ => Err(ServerlessError::InvalidTxToType),
    }?;

    // Check if the contract address matches the expected user code contract
    if !contract_address.eq_ignore_ascii_case(contract) {
        return Err(ServerlessError::InvalidTxToValue(
            contract_address,
            contract.to_owned(),
        ));
    }

    // Get the transaction data as hexadecimal string starting with '0x'
    let input = match tx_data["input"].take() {
        Value::String(input) => Ok(input),
        _ => Err(ServerlessError::InvalidTxCalldataType),
    }?;

    // Ensure the function selector is correct
    if !input.starts_with(SAVE_CODE_FUNCTION_SELECTOR) {
        return Err(ServerlessError::InvalidTxCalldata);
    }
    let input_bytes = hex::decode(&input[2..])?;

    // Create a Function object corresponding to function saveCodeInCallData(string calldata inputData, bytes calldata metadata)
    let save_code_function = Function {
        name: "saveCodeInCallData".to_string(),
        inputs: vec![
            Param {
                name: "inputData".to_string(),
                kind: ParamType::String,
                internal_type: None,
            },
            Param {
                name: "metadata".to_string(),
                kind: ParamType::Bytes,
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: Some(false),
        state_mutability: StateMutability::NonPayable,
    };

    // Now decode the data
    let Ok(tokens) = save_code_function.decode_input(&input_bytes[4..]) else {
        return Err(ServerlessError::InvalidTxCalldata);
    };

    // Extract inputData token
    let Some(code_str) = tokens[0].clone().into_string() else {
        return Err(ServerlessError::InvalidTxCalldata);
    };

    let mut code_bytes = code_str.into_bytes();

    // Strip trailing zeros in the calldata
    let idx = code_bytes.iter().rev().position(|x| *x != 0).unwrap_or(0);
    code_bytes.truncate(code_bytes.len() - idx);

    // Write calldata to the desired file location
    Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            create_and_populate_file(
                workerd_runtime_path.to_owned() + "/" + tx_hash + "-" + slug + ".js",
                code_bytes.as_slice(),
            )
            .await
        },
    )
    .await
    .map_err(ServerlessError::CodeFileCreate)?;

    Ok(())
}

pub async fn create_config_file(
    secret_store_path: &str,
    secret_id: &str,
    tx_hash: &str,
    slug: &str,
    workerd_runtime_path: &str,
    free_port: u16,
) -> Result<(), ServerlessError> {
    // Initialize the config data for user code execution by workerd runtime
    // If secret_id is 0 then no need to embed any environment variable in the execution, else bind the secret data to 'secret' variable
    let capnp_data = if secret_id == "0" {
        format!(
            "
        using Workerd = import \"/workerd/workerd.capnp\";
    
        const oysterConfig :Workerd.Config = (
          services = [ (name = \"main\", worker = .oysterWorker) ],
          sockets = [ ( name = \"http\", address = \"*:{free_port}\", http = (), service = \"main\" ) ]
        );
    
        const oysterWorker :Workerd.Worker = (
          modules = [
            (name = \"main\", esModule = embed \"{tx_hash}-{slug}.js\")
          ],
          compatibilityDate = \"2023-03-07\",
        );"
        )
    } else {
        format!(
        "
        using Workerd = import \"/workerd/workerd.capnp\";

        const oysterConfig :Workerd.Config = (
          services = [ (name = \"main\", worker = .oysterWorker) ],
          sockets = [ ( name = \"http\", address = \"*:{free_port}\", http = (), service = \"main\" ) ]
        );

        const oysterWorker :Workerd.Worker = (
          modules = [
            (name = \"main\", esModule = embed \"{tx_hash}-{slug}.js\")
          ],
          bindings = [
            (name = \"secret\", data = embed \"{secret_store_path}/{secret_id}.bin\")
          ],
          compatibilityDate = \"2023-03-07\",
        );"
        )
    };

    // Write config to the desired file location
    Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            create_and_populate_file(
                workerd_runtime_path.to_owned() + "/" + tx_hash + "-" + slug + ".capnp",
                capnp_data.as_bytes(),
            )
            .await
        },
    )
    .await
    .map_err(ServerlessError::ConfigFileCreate)?;

    Ok(())
}

// Get a free port number for the cgroup exposing the user code
pub fn get_port(cgroup: &str) -> Result<u16, ServerlessError> {
    u16::from_str_radix(&cgroup[8..], 10)
        .map(|x| x + 11000)
        .map_err(|err| {
            eprintln!(
                "Failed to get the port number for cgroup {}: {:?}",
                cgroup, err
            );
            ServerlessError::BadPort(err)
        })
}

pub async fn execute(
    tx_hash: &str,
    slug: &str,
    workerd_runtime_path: &str,
    cgroup: &str,
) -> Result<Child, ServerlessError> {
    // Initialize the arguments instructing the workerd runtime to execute the code file using the config file
    let args = [
        &(workerd_runtime_path.to_owned() + "/workerd"),
        "serve",
        &(workerd_runtime_path.to_owned() + "/" + tx_hash + "-" + slug + ".capnp"),
        "--verbose",
    ];

    Ok(Cgroups::execute(cgroup, args).map_err(|err| {
        eprintln!(
            "Failed to execute cgroups or the workerd service: {:?}",
            err
        );
        ServerlessError::Execute
    })?)
}

// Wait until the cgroup port is exposed with the user code endpoint
pub async fn wait_for_port(port: u16) -> bool {
    let start_time = Instant::now();

    while start_time.elapsed() < Duration::from_secs(1) {
        match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => return true,
            Err(_) => sleep(Duration::from_millis(1)).await,
        }
    }
    false
}

// Cleanup the user code file
pub async fn cleanup_code_file(
    tx_hash: &str,
    slug: &str,
    workerd_runtime_path: &str,
) -> Result<(), ServerlessError> {
    Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            tokio::fs::remove_file(
                workerd_runtime_path.to_owned() + "/" + tx_hash + "-" + slug + ".js",
            )
            .await
        },
    )
    .await
    .map_err(|err| {
        eprintln!("Failed to clean up the code file: {:?}", err);
        ServerlessError::CodeFileDelete(err)
    })?;

    Ok(())
}

// Cleanup the config file
pub async fn cleanup_config_file(
    tx_hash: &str,
    slug: &str,
    workerd_runtime_path: &str,
) -> Result<(), ServerlessError> {
    Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            tokio::fs::remove_file(
                workerd_runtime_path.to_owned() + "/" + tx_hash + "-" + slug + ".capnp",
            )
            .await
        },
    )
    .await
    .map_err(|err| {
        eprintln!("Failed to clean up the config file: {:?}", err);
        ServerlessError::ConfigFileDelete(err)
    })?;

    Ok(())
}

// Get response from the user code server run by the workerd runtime
pub async fn get_workerd_response(port: u16, inputs: Bytes) -> Result<Bytes, ServerlessError> {
    let port_str = port.to_string();
    let req_url = "http://127.0.0.1:".to_string() + &port_str + "/";

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .map_err(|err| {
            eprintln!("Failed to build the reqwest client: {:?}", err);
            ServerlessError::WorkerRequestError(err)
        })?;

    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async { client_call(&client, &req_url, &inputs).await },
    )
    .await
    .map_err(ServerlessError::WorkerRequestError)?)
}

// Retrieve user code data transaction data from the http rpc url
async fn get_transaction_data(tx_hash: &str, rpc: &str) -> Result<Value, reqwest::Error> {
    let client = Client::new();
    let method = "eth_getTransactionByHash";
    let params = json!([&tx_hash]);
    let id = 1;

    let request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": id,
    });

    let response = client
        .post(rpc)
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            eprintln!(
                "Failed to send the request to retrieve code transaction data: {:?}",
                err
            );
            err
        })?;

    let json_response = response.json::<Value>().await.map_err(|err| {
        eprintln!(
            "Failed to parse the response for the code transaction data: {:?}",
            err
        );
        err
    })?;

    Ok(json_response)
}

// Create and write data to a file location asynchronously
async fn create_and_populate_file(path: String, data: &[u8]) -> Result<(), tokio::io::Error> {
    let mut file = File::create(&path).await.map_err(|err| {
        eprintln!("Failed to create the file at path {}: {:?}", path, err);
        err
    })?;

    file.write_all(data).await.map_err(|err| {
        eprintln!("Failed to write to the file at path {}: {:?}", path, err);
        err
    })?;

    Ok(())
}

// Make post request to an url using the inputs provided and the reqwest client and parse the response
async fn client_call(
    client: &Client,
    req_url: &str,
    inputs: &Bytes,
) -> Result<Bytes, reqwest::Error> {
    let response = client
        .post(req_url)
        .body(inputs.to_owned())
        .send()
        .await
        .map_err(|err| {
            eprintln!("Failed to send request to the workerd port: {:?}", err);
            err
        })?;

    Ok(response.bytes().await.map_err(|err| {
        eprintln!("Failed to parse response from the worker: {:?}", err);
        err
    })?)
}
