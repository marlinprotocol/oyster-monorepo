use crate::configs::global::USDC_ADDRESS;
use alloy::{
    network::Ethereum,
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    sol,
    transports::http::Http,
};
use anyhow::{Context, Result};
use reqwest::Client;
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

/// Approves USDC transfer to the Oyster Market contract if the current allowance is insufficient
pub async fn approve_usdc(
    amount: U256,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider,
    spender: Address,
) -> Result<()> {
    let usdc_address: Address = USDC_ADDRESS
        .parse()
        .context("Failed to parse USDC address")?;

    let usdc = USDC::new(usdc_address, provider);

    info!("USDC increase allowance transaction in progress...");

    let tx_hash = usdc
        .increaseAllowance(spender, amount)
        .send()
        .await
        .context("Failed to send USDC approval transaction")?
        .watch()
        .await
        .context("Failed to get USDC approval transaction hash")?;

    info!("USDC approval transaction: {:?}", tx_hash);
    Ok(())
}
