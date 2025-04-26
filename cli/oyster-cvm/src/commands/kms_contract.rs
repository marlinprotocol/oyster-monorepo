use alloy::{
    primitives::{Address, FixedBytes},
    providers::{Provider, ProviderBuilder},
    sol,
};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use tracing::info;

use crate::{
    args::wallet::WalletArgs, configs::global::ARBITRUM_ONE_RPC_URL,
    utils::provider::create_provider,
};

// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    KmsVerifiable,
    "src/artifacts/KmsVerifiable.json"
);

/// KMS verify contract commands
#[derive(Parser)]
pub struct KmsContractArgs {
    #[command(subcommand)]
    contract_cmd: KmsContractCommands,
}

#[derive(Subcommand, Debug)]
enum KmsContractCommands {
    /// Deploy the KMS verify contract
    Deploy(KmsContractDeployArgs),
    /// Approve the image ID on KMS verify contract
    Approve(KmsActionArgs),
    /// Revoke the image ID on KMS verify contract
    Revoke(KmsActionArgs),
    /// Verify the image ID on KMS verify contract
    Verify(KmsVerifyArgs),
}

#[derive(Args, Debug)]
struct KmsContractDeployArgs {
    #[command(flatten)]
    wallet: WalletArgs,
}

#[derive(Args, Debug)]
struct KmsActionArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// KMS verify contract address
    #[arg(long)]
    contract_address: String,

    /// Image ID
    #[arg(long)]
    image_id: String,
}

#[derive(Args, Debug)]
struct KmsVerifyArgs {
    /// KMS verify contract address
    #[arg(long)]
    contract_address: String,

    /// Image ID
    #[arg(long)]
    image_id: String,
}

pub async fn kms_contract(args: KmsContractArgs) -> Result<()> {
    match args.contract_cmd {
        KmsContractCommands::Deploy(args) => kms_contract_deploy(args).await,
        KmsContractCommands::Approve(args) => kms_contract_approve(args).await,
        KmsContractCommands::Revoke(args) => kms_contract_revoke(args).await,
        KmsContractCommands::Verify(args) => kms_contract_verify(args).await,
    }
}

async fn kms_contract_deploy(args: KmsContractDeployArgs) -> Result<()> {
    // get the provider
    let provider = create_provider(&args.wallet.load_required()?).await?;

    // deploy the contract
    let contract = KmsVerifiable::deploy(provider, vec![])
        .await
        .context("Failed to deploy contract")?;

    info!("Contract deployed at: {}", contract.address());

    // TODO: get the contract verified

    Ok(())
}

async fn kms_contract_approve(args: KmsActionArgs) -> Result<()> {
    // get the provider
    let provider = create_provider(&args.wallet.load_required()?).await?;

    // create contract object
    let contract = KmsVerifiable::new(args.contract_address.parse::<Address>()?, provider.clone());

    // call the approve function
    let tx_hash = contract
        .approveImages(vec![args.image_id.parse::<FixedBytes<32>>()?])
        .send()
        .await?
        .watch()
        .await?;
    info!("Transaction hash: {:?}", tx_hash);

    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    // Add logging to check transaction status
    if !receipt.status() {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    Ok(())
}

async fn kms_contract_revoke(args: KmsActionArgs) -> Result<()> {
    // get the provider
    let provider = create_provider(&args.wallet.load_required()?).await?;

    // create contract object
    let contract = KmsVerifiable::new(args.contract_address.parse::<Address>()?, provider.clone());

    // call the revoke function
    let tx_hash = contract
        .revokeImages(vec![args.image_id.parse::<FixedBytes<32>>()?])
        .send()
        .await?
        .watch()
        .await?;
    info!("Transaction hash: {:?}", tx_hash);

    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    // Add logging to check transaction status
    if !receipt.status() {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    Ok(())
}

async fn kms_contract_verify(args: KmsVerifyArgs) -> Result<()> {
    // get the provider
    let provider = ProviderBuilder::new().with_recommended_fillers().on_http(
        ARBITRUM_ONE_RPC_URL
            .parse()
            .context("Failed to parse RPC URL")?,
    );
    // create contract object
    let contract = KmsVerifiable::new(args.contract_address.parse::<Address>()?, provider.clone());

    // call the oysterKMSVerify function
    let resp = contract
        .oysterKMSVerify(args.image_id.parse::<FixedBytes<32>>()?)
        .call()
        .await?;
    if resp._0 {
        info!("Image ID is verified");
    } else {
        info!("Image ID is not verified");
    }

    Ok(())
}
