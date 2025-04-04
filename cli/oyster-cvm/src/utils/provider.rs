use std::rc::Rc;

use crate::configs::blockchain::Blockchain;
use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::FixedBytes,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    transports::http::Http,
};
use anchor_client::{
    solana_sdk::{bs58, commitment_config::CommitmentConfig, signature::Keypair},
    Client as AnchorClient, Cluster,
};
use anyhow::{Context, Result};
use reqwest::Client;

pub async fn create_ethereum_provider(
    wallet_private_key: &str,
    blockchain: &Blockchain,
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
            blockchain
                .rpc_url()
                .parse()
                .context("Failed to parse RPC URL")?,
        );

    Ok(provider)
}

pub async fn create_solana_provider(
    wallet_private_key: &str,
    blockchain: &Blockchain,
) -> Result<AnchorClient<Rc<Keypair>>> {
    let keypair_bytes = bs58::decode(wallet_private_key)
        .into_vec()
        .context("Failed to decode private key from base58")?;

    let keypair = Keypair::from_bytes(&keypair_bytes)
        .context("Failed to create keypair from private key bytes")?;

    // Set up the client with the keypair
    let cluster = Cluster::Custom(
        blockchain.rpc_url().to_string(),
        blockchain.rpc_url().to_string(),
    );
    let provider =
        AnchorClient::new_with_options(cluster, Rc::new(keypair), CommitmentConfig::confirmed());

    Ok(provider)
}
