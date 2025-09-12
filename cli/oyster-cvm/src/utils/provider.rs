use crate::configs::global::ARBITRUM_ONE_RPC_URL;
use alloy::{
    network::EthereumWallet,
    primitives::FixedBytes,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};

pub async fn create_provider(
    wallet_private_key: &str,
) -> Result<impl Provider + WalletProvider + Clone + use<>> {
    let private_key = FixedBytes::<32>::from_slice(
        &hex::decode(wallet_private_key).context("Failed to decode private key")?,
    );

    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Failed to create signer from private key")?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(
        ARBITRUM_ONE_RPC_URL
            .parse()
            .context("Failed to parse RPC URL")?,
    );

    Ok(provider)
}
