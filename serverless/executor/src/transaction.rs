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
                            + output_txn_deadline(
                                app_state.execution_buffer_time,
                                deadline,
                                call._totalTime.as_limbs()[0],
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

// Time left for the output to be accepted by the 'Jobs' contract
// Execution buffer time is in secs, the user deadline and the execution time are in millis
fn output_txn_deadline(
    execution_buffer_time: u64,
    user_deadline: u64,
    total_time: u64,
) -> Duration {
    Duration::from_secs(execution_buffer_time)
        + Duration::from_millis(user_deadline.saturating_sub(total_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_txn_deadline_test() {
        assert_eq!(
            output_txn_deadline(60, 50000, 100),
            Duration::from_millis(109900)
        );
        assert_eq!(output_txn_deadline(60, 5000, 5000), Duration::from_secs(60));
        assert_eq!(output_txn_deadline(60, 5000, 5001), Duration::from_secs(60));
    }
}
