use std::{rc::Rc, time::Duration};

use anchor_client::{
    solana_sdk::signature::{Keypair, Signature},
    Program,
};
use anchor_lang::prelude::Pubkey;
use anchor_spl::{
    associated_token::spl_associated_token_account::instruction::create_associated_token_account,
    token,
};
use anyhow::{anyhow, Result};
use solana_transaction_status_client_types::UiTransactionEncoding;
use tokio::time::sleep;
use tracing::{error, info};

use crate::configs::blockchain::SOLANA_TRANSACTION_CONFIG;

pub async fn create_all_associated_token_accounts(
    user_address: &Pubkey,
    operator_address: &Pubkey,
    token_mint: &Pubkey,
    credit_mint: &Pubkey,
    program: &Program<Rc<Keypair>>,
) -> Result<()> {
    let user_token_account =
        create_associated_token_account(user_address, user_address, token_mint, &token::ID);

    let signature = program
        .request()
        .instruction(user_token_account)
        .send_with_spinner_and_config(SOLANA_TRANSACTION_CONFIG)
        .await;

    if let Err(e) = signature {
        let rpc_client_error_provided_owner_not_allowed = "RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: Provided owner is not allowed;";
        if !e
            .to_string()
            .contains(rpc_client_error_provided_owner_not_allowed)
        {
            error!("Error Creating User Token Account: {:#?}", e.to_string());
            return Err(anyhow!("Error Creating User Token Account"));
        }
    }

    let provider_token_account =
        create_associated_token_account(user_address, operator_address, token_mint, &token::ID);

    let signature = program
        .request()
        .instruction(provider_token_account)
        .send_with_spinner_and_config(SOLANA_TRANSACTION_CONFIG)
        .await;

    if let Err(e) = signature {
        let rpc_client_error_provided_owner_not_allowed = "RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: Provided owner is not allowed;";
        if !e
            .to_string()
            .contains(rpc_client_error_provided_owner_not_allowed)
        {
            error!(
                "Error Creating Provider Token Account: {:#?}",
                e.to_string()
            );
            return Err(anyhow!("Error Creating Provider Token Account"));
        }
    }

    let user_credit_token_account =
        create_associated_token_account(user_address, user_address, credit_mint, &token::ID);

    let signature = program
        .request()
        .instruction(user_credit_token_account)
        .send_with_spinner_and_config(SOLANA_TRANSACTION_CONFIG)
        .await;

    if let Err(e) = signature {
        let rpc_client_error_provided_owner_not_allowed = "RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: Provided owner is not allowed;";
        if !e
            .to_string()
            .contains(rpc_client_error_provided_owner_not_allowed)
        {
            error!(
                "Error Creating User Credit Token Account: {:#?}",
                e.to_string()
            );
            return Err(anyhow!("Error Creating User Credit Token Account"));
        }
    }

    Ok(())
}

pub async fn fetch_transaction_receipt_with_retry(
    program: Program<Rc<Keypair>>,
    signature: &Signature,
) -> Result<()> {
    // sleep for 20 seconds
    info!("Sleeping for 20 seconds before fetching transaction receipt");
    sleep(Duration::from_secs(20)).await;

    let mut receipt = None;
    let mut attempts = 0;
    let max_attempts = 5;

    while attempts < max_attempts {
        attempts += 1;
        info!(
            "Fetching transaction receipt (attempt {}/{})",
            attempts, max_attempts
        );

        let receipt_result = program
            .rpc()
            .get_transaction(signature, UiTransactionEncoding::Json)
            .await;

        match receipt_result {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            Err(e) => {
                if attempts == max_attempts {
                    return Err(anyhow!("Failed to get transaction receipt: {:?}", e));
                }
                info!("Failed to get receipt, retrying in 5 seconds: {:?}", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }

    let receipt = receipt.unwrap();

    if receipt.transaction.meta.is_none() {
        return Err(anyhow!("Failed to get transaction meta"));
    }

    let meta = receipt.transaction.meta.unwrap();

    if meta.err.is_some() {
        return Err(anyhow!("Transaction failed: {:?}", meta.err.unwrap()));
    }

    info!("Transaction successful");

    Ok(())
}
