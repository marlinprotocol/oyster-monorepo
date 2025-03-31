use std::rc::Rc;

use anchor_client::{solana_sdk::signature::Keypair, Program};
use anchor_lang::prelude::Pubkey;
use anchor_spl::{
    associated_token::spl_associated_token_account::instruction::create_associated_token_account,
    token,
};
use anyhow::{anyhow, Result};
use tracing::error;

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
        .send()
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
        .send()
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
        .send()
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
