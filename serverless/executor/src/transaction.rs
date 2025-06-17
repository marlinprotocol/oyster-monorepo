use std::time::{Duration, Instant};

use alloy::sol_types::SolCall;
use axum::extract::State;
use tokio::sync::mpsc::Receiver;

use crate::{
    constant::TIMEOUT_TXN_RESEND_DEADLINE_SECS,
    model::{AppState, JobsTransaction},
};

pub async fn send_transaction(
    app_state: State<AppState>,
    mut tx_receiver: Receiver<JobsTransaction>,
) {
    while let Some(job_response) = tx_receiver.recv().await {
        let http_rpc_txn_manager = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        match job_response {
            JobsTransaction::OUTPUT(call, deadline) => {
                if let Err(err) = http_rpc_txn_manager
                    .call_contract_function(
                        app_state.jobs_contract_addr,
                        call.abi_encode().into(),
                        Instant::now()
                            + Duration::from_secs(
                                app_state.execution_buffer_time + deadline
                                    - call._totalTime.as_limbs()[0],
                            ),
                    )
                    .await
                {
                    eprintln!(
                        "Failed to call 'Jobs' contract function with transaction manager: {:?}",
                        err
                    );
                };
            }
            JobsTransaction::TIMEOUT(call) => {
                if let Err(err) = http_rpc_txn_manager
                    .call_contract_function(
                        app_state.jobs_contract_addr,
                        call.abi_encode().into(),
                        Instant::now() + Duration::from_secs(TIMEOUT_TXN_RESEND_DEADLINE_SECS),
                    )
                    .await
                {
                    eprintln!(
                        "Failed to call 'Jobs' contract function with transaction manager: {:?}",
                        err
                    );
                };
            }
        }
    }

    println!("Executor transaction sender channel stopped!");
    return;
}
