use crate::configs;
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    sol,
};
use anyhow::{Context, Result, anyhow};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/token_abi.json"
);

/// Approves USDC transfer to the Oyster Market contract if the current allowance is insufficient
pub async fn approve_usdc(
    deployment: &str,
    amount: U256,
    provider: impl Provider + WalletProvider,
) -> Result<()> {
    let usdc_address = match deployment {
        "arb1" => configs::arb::USDC_ADDRESS.parse::<Address>()?,
        "bsc" => configs::bsc::USDC_ADDRESS.parse::<Address>()?,
        _ => Err(anyhow!("unknown deployment"))?,
    };
    let market_address = match deployment {
        "arb1" => configs::arb::OYSTER_MARKET_ADDRESS.parse::<Address>()?,
        "bsc" => configs::bsc::OYSTER_MARKET_ADDRESS.parse::<Address>()?,
        _ => Err(anyhow!("unknown deployment"))?,
    };
    let signer_address = provider
        .signer_addresses()
        .next()
        .ok_or_else(|| anyhow!("No signer address found"))?;
    let usdc = USDC::new(usdc_address, provider);

    // Get the current allowance
    let current_allowance = usdc
        .allowance(signer_address, market_address)
        .call()
        .await
        .context("Failed to get current USDC allowance")?;

    // Only approve if the current allowance is less than the required amount
    if current_allowance < amount {
        info!(
            "Current allowance ({}) is less than required amount ({}), approving USDC transfer...",
            current_allowance, amount
        );
        let tx_hash = usdc
            .approve(market_address, amount)
            .send()
            .await
            .context("Failed to send USDC approval transaction")?
            .watch()
            .await
            .context("Failed to get USDC approval transaction hash")?;

        info!("USDC approval transaction: {:?}", tx_hash);
    } else {
        info!(
            "Current allowance ({}) is sufficient for the required amount ({}), skipping approval",
            current_allowance, amount
        );
    }
    Ok(())
}

/// Formats a U256 value as USDC with 6 decimal places
pub fn format_usdc(value: U256) -> f64 {
    value.to::<u128>() as f64 / 1e6
}
