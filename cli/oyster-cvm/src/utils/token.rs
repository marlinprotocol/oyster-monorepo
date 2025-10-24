use crate::utils::credit::{approve_credit, get_credit_balance};
use crate::utils::usdc::{approve_usdc, format_usdc};
use alloy::{
    network::Ethereum,
    primitives::U256,
    providers::{Provider, WalletProvider},
    transports::http::Http,
};
use anyhow::{anyhow, Result};
use reqwest::Client;
use tracing::info;

pub async fn approve_total_cost(
    total_cost: U256,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider + Clone,
) -> Result<()> {
    let credit_balance = match get_credit_balance(provider.clone()).await {
        Ok(balance) => balance,
        Err(_) => {
            return Err(anyhow!("Failed to get credit balance from Contract"));
        }
    };

    let credit_amount = std::cmp::min(credit_balance, total_cost);
    let token_amount = total_cost - credit_amount;

    if credit_amount > U256::from(0) {
        info!("Using {} credits", format_usdc(credit_amount));
        approve_credit(credit_amount, provider.clone()).await?;
    }
    if token_amount > U256::from(0) {
        info!("Using {} USDC", format_usdc(token_amount));
        approve_usdc(token_amount, provider.clone()).await?;
    }

    Ok(())
}
