use crate::configs::global::ARBITRUM_ONE_RPC_URL;
use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::FixedBytes,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    transports::http::Http,
};
use anyhow::{Context, Result};
use reqwest::Client;

pub async fn create_provider(
    wallet_private_key: &str,
) -> Result<impl Provider<Http<Client>, Ethereum> + WalletProvider + Clone> {
    let private_key = FixedBytes::<32>::from_slice(
        &hex::decode(wallet_private_key).context("Failed to decode private key")?,
    );

    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Failed to create signer from private key")?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            ARBITRUM_ONE_RPC_URL
                .parse()
                .context("Failed to parse RPC URL")?,
        );

    Ok(provider)
}
