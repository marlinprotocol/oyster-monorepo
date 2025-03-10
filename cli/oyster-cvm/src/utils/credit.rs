use crate::configs::global::{CREDIT_ADDRESS, OYSTER_MARKET_ADDRESS};
use alloy::{
    primitives::{Address, U256},
    providers::WalletProvider,
    sol,
};
use anyhow::{anyhow, Context, Result};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CREDIT,
    "src/abis/credit_abi.json"
);

pub async fn get_credit_balance(provider: crate::utils::provider::OysterProvider) -> Result<U256> {
    let credit_address: Address = CREDIT_ADDRESS
        .parse()
        .context("Failed to parse credit address")?;

    let credit = CREDIT::new(credit_address, provider.clone());
    let signer_address = provider
        .signer_addresses()
        .next()
        .ok_or_else(|| anyhow!("No signer address found"))?;

    let balance = credit
        .balanceOf(signer_address)
        .call()
        .await
        .context("Failed to get credit balance")?;

    Ok(balance._0)
}

pub async fn approve_credit(
    amount: U256,
    provider: crate::utils::provider::OysterProvider,
) -> Result<()> {
    let credit_address: Address = CREDIT_ADDRESS
        .parse()
        .context("Failed to parse credit address")?;
    let market_address: Address = OYSTER_MARKET_ADDRESS
        .parse()
        .context("Failed to parse market address")?;
    let signer_address = provider
        .signer_addresses()
        .next()
        .ok_or_else(|| anyhow!("No signer address found"))?;
    let credit = CREDIT::new(credit_address, provider);

    // Get the current allowance
    let current_allowance_result = credit
        .allowance(signer_address, market_address)
        .call()
        .await
        .context("Failed to get current credit allowance")?;

    // Extract numeric allowance value
    let current_allowance: U256 = current_allowance_result._0;

    // Only approve if the current allowance is less than the required amount
    if current_allowance < amount {
        info!(
            "Current allowance ({}) is less than required amount ({}), approving credit transfer...",
            current_allowance, amount
        );
        let tx_hash = credit
            .approve(market_address, amount)
            .send()
            .await
            .context("Failed to send credit approval transaction")?
            .watch()
            .await
            .context("Failed to get credit approval transaction hash")?;

        info!("Credit approval transaction: {:?}", tx_hash);
    } else {
        info!(
            "Current allowance ({}) is sufficient for the required amount ({}), skipping approval",
            current_allowance, amount
        );
    }
    Ok(())
}
