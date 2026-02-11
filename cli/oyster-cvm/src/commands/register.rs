use anyhow::{Context, Result, anyhow};
use clap::Args;
use oyster::attestation::get;
use std::str::FromStr;
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
    TransactionKind,
};
use tracing::info;

use crate::args::wallet::WalletArgs;
use crate::configs::sui::*;
use crate::deployment::Deployment;
use crate::deployment::adapter::{ChainProvider, ChainTransaction, DeploymentAdapter};
use crate::deployment::sui::{SuiAdapter, kind_to_transaction};

/// Register an Oyster CVM instance on SUI chain
#[derive(Args)]
pub struct RegisterArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Deployment (e.g. sui)
    #[arg(long, default_value = "sui")]
    deployment: Deployment,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,

    /// Oyster CVM instance IP, e.g. 100.26.111.45
    #[arg(long)]
    enclave_ip: String,

    /// Attestation Port (default: 1301)
    #[arg(long, default_value_t = 1301)]
    attestation_port: u16,
}

pub async fn register_oyster_instance(args: RegisterArgs) -> Result<()> {
    if args.deployment != Deployment::Sui {
        return Err(anyhow!(
            "Register enclave only supported for Sui based deployment currently"
        ));
    }

    info!("Fetching attestation document for the instance...");

    let attestation_endpoint = format!(
        "http://{}:{}/attestation/raw",
        args.enclave_ip, args.attestation_port
    );
    info!(
        "Connecting to attestation endpoint: {}",
        attestation_endpoint
    );

    let attestation_doc = get(attestation_endpoint
        .parse()
        .context("Failed to parse enclave attestation endpoint")?)
    .await
    .context("Failed to fetch attestation document")?;
    info!("Successfully fetched attestation document");

    let wallet_private_key = &args
        .wallet
        .load_required()
        .context("Failed to load the wallet file")?;
    let mut sui_adapter = get_sui_adapter(
        args.rpc,
        args.auth_token,
        None,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    // Setup provider
    let mut provider = match sui_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?
    {
        ChainProvider::Sui(provider) => provider,
        ChainProvider::Evm(_) => return Err(anyhow!("Internal error")),
    };

    let signer_address = Address::from_str(&sui_adapter.get_sender_address())
        .context("Failed to parse signer address")?;
    info!("Signer address: {:?}", signer_address);

    let tx_kind = generate_transaction_kind(attestation_doc)?;

    let transaction = Box::new(
        kind_to_transaction(
            &mut provider.client,
            tx_kind,
            signer_address,
            sui_adapter.gas_coin_id,
        )
        .await
        .context("Failed to build the register transaction")?,
    );

    let _ = sui_adapter
        .send_transaction(
            false,
            ChainTransaction::Sui(transaction),
            &ChainProvider::Sui(provider.clone()),
        )
        .await
        .context("Failed to send register transaction")?;

    info!("Enclave registered successfully!");
    Ok(())
}

fn get_sui_adapter(
    rpc_url: Option<String>,
    auth_token: Option<String>,
    usdc_coin: Option<Address>,
    gas_coin: Option<Address>,
) -> SuiAdapter {
    SuiAdapter {
        rpc_url: rpc_url.unwrap_or(SUI_GRPC_URL.to_owned()),
        auth_token,
        market_package_id: Address::from_static(OYSTER_MARKET_PACKAGE_ID),
        market_package_initial_version: OYSTER_MARKET_PACKAGE_INITIAL_VERSION,
        market_config_id: Address::from_static(OYSTER_MARKET_CONFIG_ID),
        market_place_id: Address::from_static(OYSTER_MARKET_PLACE_ID),
        lock_data_id: Address::from_static(OYSTER_MARKET_LOCK_DATA_ID),
        usdc_id: Address::from_static(USDC_PACKAGE_ID),
        clock_id: Address::from_static(SUI_CLOCK_ID),
        clock_initial_shared_version: SUI_CLOCK_INITIAL_VERSION,
        usdc_coin_id: usdc_coin,
        gas_coin_id: gas_coin,
        sender_address: None,
    }
}

fn generate_transaction_kind(attestation: Box<[u8]>) -> Result<TransactionKind> {
    // Build the PTB with the two move calls,
    // 1) 0x2::nitro_attestation::load_nitro_attestation(attestation: vector<u8>, &Clock)
    // 2) PACKAGE_ID::enclave_registry::register_enclave({REGISTRY_ID}, NitroAttestationDocument)
    let attestation_call = MoveCall {
        package: Address::from_static("0x2"),
        module: Identifier::from_static("nitro_attestation"),
        function: Identifier::from_static("load_nitro_attestation"),
        type_arguments: vec![],
        arguments: vec![Argument::Input(0), Argument::Input(1)],
    };

    let register_call = MoveCall {
        package: Address::from_static(OYSTER_ENCLAVE_REGISTRY_PACKAGE_ID),
        module: Identifier::from_static(OYSTER_ENCLAVE_REGISTRY_PACKAGE_NAME),
        function: Identifier::from_static(OYSTER_ENCLAVE_REGISTER_METHOD_NAME),
        type_arguments: vec![],
        arguments: vec![Argument::Input(2), Argument::Result(0)],
    };

    // Build the transaction kind
    Ok(TransactionKind::ProgrammableTransaction(
        ProgrammableTransaction {
            commands: vec![
                Command::MoveCall(attestation_call),
                Command::MoveCall(register_call),
            ],
            inputs: vec![
                Input::Pure {
                    value: bcs::to_bytes(&attestation)
                        .context("Failed to bcs encode attestation bytes")?,
                },
                Input::Shared {
                    object_id: Address::from_static(SUI_CLOCK_ID),
                    initial_shared_version: SUI_CLOCK_INITIAL_VERSION,
                    mutable: false,
                },
                Input::Shared {
                    object_id: Address::from_static(REGISTRY_ID),
                    initial_shared_version: REGISTRY_INITIAL_VERSION,
                    mutable: true,
                },
            ],
        },
    ))
}
