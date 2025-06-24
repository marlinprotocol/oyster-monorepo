use std::time::{Duration, Instant};

use actix_web::web::Data;
use alloy::sol_types::SolCall;
use tokio::sync::mpsc::Receiver;

use crate::{
    constants::{ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE_SECS, SEND_TRANSACTION_BUFFER_SECS},
    model::{AppState, StoresTransaction},
};

pub async fn send_transaction(
    app_state: Data<AppState>,
    mut tx_receiver: Receiver<StoresTransaction>,
) {
    while let Some(transaction) = tx_receiver.recv().await {
        let http_rpc_txn_manager = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        match transaction {
            StoresTransaction::AcknowledgeStore(call, deadline) => {
                if let Err(err) = http_rpc_txn_manager
                    .call_contract_function(
                        app_state.secret_manager_contract_addr,
                        call.abi_encode().into(),
                        deadline,
                    )
                    .await
                {
                    eprintln!(
                        "Failed to call 'SecretManager' contract function with transaction manager: {:?}",
                        err
                    );
                };
            }
            StoresTransaction::AcknowledgeStoreFailed(call) => {
                if let Err(err) = http_rpc_txn_manager
                    .call_contract_function(
                        app_state.secret_manager_contract_addr,
                        call.abi_encode().into(),
                        Instant::now()
                            + Duration::from_secs(ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE_SECS),
                    )
                    .await
                {
                    eprintln!(
                        "Failed to call 'SecretManager' contract function with transaction manager: {:?}",
                        err
                    );
                };
            }
            StoresTransaction::MarkStoreAlive(call) => {
                if let Err(err) = http_rpc_txn_manager
                    .call_contract_function(
                        app_state.secret_manager_contract_addr,
                        call.abi_encode().into(),
                        Instant::now() + Duration::from_secs(SEND_TRANSACTION_BUFFER_SECS),
                    )
                    .await
                {
                    eprintln!(
                        "Failed to call 'SecretManager' contract function with transaction manager: {:?}",
                        err
                    );
                };
            }
        }
    }

    println!("Secret store transaction sender channel stopped!");
    return;
}
