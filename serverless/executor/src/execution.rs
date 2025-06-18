use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::U256;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::eip712_domain;
use anyhow::Context;
use axum::extract::State;
use scopeguard::defer;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

use crate::constant::MAX_OUTPUT_BYTES_LENGTH;
use crate::model::JobsContract::submitOutputCall;
use crate::model::{AppState, JobOutput, JobsTransaction, SubmitOutput};
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
    code_inputs: Vec<u8>,
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
    let mut job_output = Some(JobOutput {
        output: Vec::new(),
        error_code: 4,
        total_time: user_deadline.into(),
    });
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
        job_output.output.clone(),
        job_output.total_time,
        job_output.error_code,
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
                _output: job_output.output.into(),
                _totalTime: U256::from(job_output.total_time),
                _errorCode: job_output.error_code,
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
    code_inputs: Vec<u8>,
    slug: &String,
    app_state: State<AppState>,
) -> Option<JobOutput> {
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
            TxNotFound | InvalidTxToType | InvalidTxToValue(_, _) => Some(JobOutput {
                output: Vec::new(),
                error_code: 1,
                total_time: execution_timer_start.elapsed().as_millis(),
            }),
            InvalidTxCalldata | InvalidTxCalldataType | BadCalldata(_) => Some(JobOutput {
                output: Vec::new(),
                error_code: 2,
                total_time: execution_timer_start.elapsed().as_millis(),
            }),
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
            return Some(JobOutput {
                output: Vec::new(),
                error_code: 3,
                total_time: execution_timer_start.elapsed().as_millis(),
            });
        }

        eprintln!("Failed to execute worker service to serve the user code: {stderr_output}");

        return None;
    }

    // Worker is ready, Make the request with the expected user timeout
    let Ok(response) = workerd::get_workerd_response(port, code_inputs.into()).await else {
        return None;
    };

    if response.len() > MAX_OUTPUT_BYTES_LENGTH {
        return Some(JobOutput {
            output: Vec::new(),
            error_code: 5,
            total_time: execution_timer_start.elapsed().as_millis(),
        });
    }

    Some(JobOutput {
        output: response,
        error_code: 0,
        total_time: execution_timer_start.elapsed().as_millis(),
    })
}

// Sign the execution response with the enclave key to be verified by the jobs contract
fn sign_response(
    signer_key: &PrivateKeySigner,
    job_id: U256,
    output: Vec<u8>,
    total_time: u128,
    error_code: u8,
    sign_timestamp: U256,
) -> Option<Vec<u8>> {
    let submit_output_data = SubmitOutput {
        jobId: job_id,
        output: output.into(),
        totalTime: U256::from(total_time),
        errorCode: error_code,
        signTimestamp: U256::from(sign_timestamp),
    };

    let domain_separator = eip712_domain! {
        name: "marlin.oyster.Jobs",
        version: "1",
    };

    // Sign the response details using enclave key
    let Ok(sig) = signer_key
        .sign_typed_data_sync(&submit_output_data, &domain_separator)
        .map_err(|err| {
            eprintln!("Failed to sign the job response: {:?}", err);
            err
        })
    else {
        return None;
    };

    Some(sig.as_bytes().to_vec())
}
