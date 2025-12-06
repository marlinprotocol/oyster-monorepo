use crate::configs;
use alloy::{
    network::EthereumWallet,
    primitives::FixedBytes,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result, anyhow};

pub async fn create_provider(
    deployment: &str,
    wallet_private_key: &str,
) -> Result<impl Provider + WalletProvider + Clone + use<>> {
    let private_key = FixedBytes::<32>::from_slice(
        &hex::decode(wallet_private_key).context("Failed to decode private key")?,
    );

    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Failed to create signer from private key")?;
    let wallet = EthereumWallet::from(signer);

    let rpc_url = match deployment {
        "arb1" => configs::arb::ARBITRUM_ONE_RPC_URL,
        "bsc" => configs::bsc::ARBITRUM_ONE_RPC_URL,
        _ => Err(anyhow!("unknown deployment"))?,
    };
    let provider = ProviderBuilder::default()
        .with_gas_estimation()
        .with_simple_nonce_management()
        .fetch_chain_id()
        .wallet(wallet)
        .connect_http(rpc_url.parse().context("Failed to parse RPC URL")?);

    Ok(provider)
}
