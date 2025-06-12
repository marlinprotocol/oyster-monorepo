use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, U256};
use anyhow::Context;
use axum::extract::State;
use bytes::Bytes;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use scopeguard::defer;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

use crate::constant::MAX_OUTPUT_BYTES_LENGTH;
use crate::model::JobsContract::submitOutputCall;
use crate::model::{AppState, JobsTransaction};
use crate::workerd;
use crate::workerd::ServerlessError::*;

/* Error code semantics:-
1 => Provided txn hash doesn't belong to the expected rpc chain or code contract
2 => Calldata corresponding to the txn hash is invalid
3 => Syntax error in the code extracted from the calldata
4 => User timeout exceeded
5 => Output size exceeds the limit
*/

// Execute the job request using workerd runtime and 'cgroup' environment
pub async fn handle_job(
    job_id: U256,
    secret_id: U256,
    code_hash: String,
    code_inputs: Bytes,
    user_deadline: u64, // time in millis
    app_state: State<AppState>,
    tx_sender: Sender<JobsTransaction>,
) {
    let slug = &hex::encode(rand::random::<u32>().to_ne_bytes());

    // Execute the job request under the specified user deadline
    let response = timeout(
        Duration::from_millis(user_deadline),
        execute_job(secret_id, &code_hash, code_inputs, slug, app_state.clone()),
    )
    .await;

    // clean up resources in case the timeout exceeds
    let _ = workerd::cleanup_config_file(&code_hash, slug, &app_state.workerd_runtime_path).await;
    let _ = workerd::cleanup_code_file(&code_hash, slug, &app_state.workerd_runtime_path).await;

    // Initialize the default timeout response and build on that based on the above response
    let mut job_output = Some((Bytes::new(), 4, user_deadline.into()));
    if response.is_ok() {
        job_output = response.unwrap();
    }

    let Some(job_output) = job_output else {
        return;
    };

    // Sign and send the job response to the receiver channel
    let sign_timestamp = U256::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let Some(signature) = sign_response(
        &app_state.enclave_signer,
        job_id,
        &job_output.0,
        job_output.2,
        job_output.1,
        sign_timestamp,
    ) else {
        return;
    };

    // Send the txn response with the execution timeout counterpart to the common chain txn sender
    if let Err(err) = tx_sender
        .send(JobsTransaction::OUTPUT(
            submitOutputCall {
                _signature: signature.into(),
                _jobId: job_id,
                _output: job_output.0.into(),
                _totalTime: U256::from(job_output.2),
                _errorCode: job_output.1,
                _signTimestamp: sign_timestamp,
            },
            user_deadline,
        ))
        .await
    {
        eprintln!(
            "Failed to send execution response transaction for job ID {}: {:?}",
            job_id, err
        );
    };

    return;
}

async fn execute_job(
    secret_id: U256,
    code_hash: &String,
    code_inputs: Bytes,
    slug: &String,
    app_state: State<AppState>,
) -> Option<(Bytes, u8, u128)> {
    let execution_timer_start = Instant::now();

    // Create the code file in the desired location
    if let Err(err) = workerd::create_code_file(
        &code_hash,
        slug,
        &app_state.workerd_runtime_path,
        &app_state.http_rpc_url,
        &app_state.code_contract_addr,
    )
    .await
    {
        return match err {
            TxNotFound | InvalidTxToType | InvalidTxToValue(_, _) => {
                Some((Bytes::new(), 1, execution_timer_start.elapsed().as_millis()))
            }
            InvalidTxCalldata | InvalidTxCalldataType | BadCalldata(_) => {
                Some((Bytes::new(), 2, execution_timer_start.elapsed().as_millis()))
            }
            _ => None,
        };
    }

    // Reserve a 'cgroup' for code execution
    let Ok(cgroup) = app_state.cgroups.lock().unwrap().reserve() else {
        eprintln!("No free cgroup available to execute the job");
        return None;
    };

    // clean up resources in case the timeout exceeds
    let cgroup_clone = cgroup.clone();
    defer! {
        app_state.cgroups.lock().unwrap().release(cgroup_clone);
    }

    // Get free port for the 'cgroup'
    let Ok(port) = workerd::get_port(&cgroup) else {
        return None;
    };

    // Create config file in the desired location
    if let Err(_) = workerd::create_config_file(
        &app_state.secret_store_path,
        &secret_id.to_string(),
        &code_hash,
        slug,
        &app_state.workerd_runtime_path,
        port,
    )
    .await
    {
        return None;
    }

    // Start workerd execution on the user code file using the config file
    let Ok(child) =
        workerd::execute(&code_hash, slug, &app_state.workerd_runtime_path, &cgroup).await
    else {
        return None;
    };
    let child = Arc::new(Mutex::new(child));

    // clean up resources in case the timeout exceeds
    defer! {
        // Kill the worker
        child
            .lock()
            .unwrap()
            .kill()
            .context("CRITICAL: Failed to kill worker {cgroup}")
            .unwrap_or_else(|err| println!("{err:?}"));
    }

    // Wait for worker to be available to receive inputs
    let res = workerd::wait_for_port(port).await;

    if !res {
        let Some(stderr) = child.lock().unwrap().stderr.take() else {
            eprintln!("Failed to retrieve cgroup execution error");
            return None;
        };
        let reader = BufReader::new(stderr);
        let stderr_lines: Vec<String> = reader
            .lines()
            .filter(|l| l.is_ok())
            .map(|l| l.unwrap())
            .collect();
        let stderr_output = stderr_lines.join("\n");

        // Check if there was a syntax error in the user code
        if stderr_output != "" && stderr_output.contains("SyntaxError") {
            return Some((Bytes::new(), 3, execution_timer_start.elapsed().as_millis()));
        }

        eprintln!("Failed to execute worker service to serve the user code: {stderr_output}");

        return None;
    }

    // Worker is ready, Make the request with the expected user timeout
    let Ok(response) = workerd::get_workerd_response(port, code_inputs).await else {
        return None;
    };

    if response.len() > MAX_OUTPUT_BYTES_LENGTH {
        return Some((Bytes::new(), 5, execution_timer_start.elapsed().as_millis()));
    }

    Some((response, 0, execution_timer_start.elapsed().as_millis()))
}

// Sign the execution response with the enclave key to be verified by the jobs contract
fn sign_response(
    signer_key: &SigningKey,
    job_id: U256,
    output: &Bytes,
    total_time: u128,
    error_code: u8,
    sign_timestamp: U256,
) -> Option<Vec<u8>> {
    // Encode and hash the job response details following EIP712 format
    let domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.Jobs"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );
    let submit_output_typehash = keccak256("SubmitOutput(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)");

    let hash_struct = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(submit_output_typehash, 32),
            DynSolValue::Uint(job_id, 256),
            DynSolValue::FixedBytes(keccak256(output), 256),
            DynSolValue::Uint(U256::from(total_time), 256),
            DynSolValue::Uint(U256::from(error_code), 256),
            DynSolValue::Uint(U256::from(sign_timestamp), 256),
        ])
        .abi_encode(),
    );

    // Create the digest
    let digest = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::String("\x19\x01".to_string()),
            DynSolValue::FixedBytes(domain_separator, 32),
            DynSolValue::FixedBytes(hash_struct, 32),
        ])
        .abi_encode_packed(),
    );

    // Sign the response details using enclave key
    let Ok((rs, v)) = signer_key
        .sign_prehash_recoverable(&digest.to_vec())
        .map_err(|err| {
            eprintln!("Failed to sign the job response: {:?}", err);
            err
        })
    else {
        return None;
    };

    Some(rs.to_bytes().append(27 + v.to_byte()).to_vec())
}
