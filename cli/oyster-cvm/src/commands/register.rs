use anyhow::{Context, Result, anyhow};
use clap::Args;
use reqwest::Client;
use std::str::FromStr;
use std::time::Duration;
use sui_rpc::field::FieldMask;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
    TransactionKind, TypeTag,
};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::args::wallet::WalletArgs;
use crate::chain::ChainType;
use crate::chain::adapter::{ChainAdapter, ChainProvider, ChainTransaction};
use crate::chain::sui::SuiAdapter;
use crate::configs::sui::*;

const ATTESTATION_RETRIES: u32 = 6;
const ATTESTATION_INTERVAL: u64 = 15;

/// Register an Oyster CVM instance on chain
#[derive(Args)]
pub struct RegisterArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Chain (e.g. arb, sui, bsc)
    #[arg(long)]
    chain: ChainType,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,

    /// Enclave move package id
    #[arg(long)]
    enclave_package_id: String,

    /// App package id (where OTW type lives)
    #[arg(long)]
    app_package_id: String,

    /// Enclave config object id
    #[arg(long)]
    enclave_config_id: String,

    /// Oyster CVM instance IP, e.g. 100.26.111.45
    #[arg(long)]
    enclave_ip: String,

    /// Module name that defines your OTW type
    #[arg(long)]
    module_name: String,

    /// OTW type name (struct name)
    #[arg(long)]
    otw_name: String,
}

pub async fn register_oyster_instance(args: RegisterArgs) -> Result<()> {
    info!("Fetching attestation document for the instance...");

    let Some(attestation) = fetch_attestation(&args.enclave_ip).await else {
        return Err(anyhow!(
            "Failed to fetch the attestation doc from the enclave"
        ));
    };

    info!("Attestation successfully fetched!");

    if args.chain.as_str() != "sui" {
        return Err(anyhow!(
            "Register enclave only supported for Sui based deployment"
        ));
    }

    let wallet_private_key = &args.wallet.load_required()?;
    let mut sui_adapter = SuiAdapter {
        rpc_url: args.rpc.unwrap_or(SUI_GRPC_URL.to_owned()),
        auth_token: args.auth_token,
        market_package_id: Address::from_static(OYSTER_MARKET_PACKAGE_ID),
        market_package_initial_version: OYSTER_MARKET_PACKAGE_INITIAL_VERSION,
        market_config_id: Address::from_static(OYSTER_MARKET_CONFIG_ID),
        market_place_id: Address::from_static(OYSTER_MARKET_PLACE_ID),
        lock_data_id: Address::from_static(OYSTER_MARKET_LOCK_DATA_ID),
        usdc_id: Address::from_static(USDC_PACKAGE_ID),
        clock_id: Address::from_static(SUI_CLOCK_ID),
        clock_initial_shared_version: SUI_CLOCK_INITIAL_VERSION,
        usdc_coin_id: None,
        gas_coin_id: args
            .gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
        sender_address: None,
    };

    // Setup provider
    let mut provider = match sui_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?
    {
        ChainProvider::Sui(provider) => provider,
        ChainProvider::Evm(_) => return Err(anyhow!("Internal error")),
    };

    let sender = sui_adapter
        .sender_address
        .ok_or_else(|| anyhow!("Sender address empty"))?;

    info!("Signer address: {:?}", sender);

    // Build the PTB with the two move calls,
    // 1) 0x2::nitro_attestation::load_nitro_attestation(attestation: vector<u8>, &Clock)
    // 2) ENCLAVE_PKG::enclave::register_enclave_secp256k1<T>(&EnclaveConfig<T>, NitroAttestationDocument)
    let attestation_call = MoveCall {
        package: Address::from_static("0x2"),
        module: Identifier::from_static("nitro_attestation"),
        function: Identifier::from_static("load_nitro_attestation"),
        type_arguments: vec![],
        arguments: vec![Argument::Input(0), Argument::Input(1)],
    };

    let t_type_str = format!(
        "{}::{}::{}",
        args.app_package_id, args.module_name, args.otw_name
    );
    let register_call = MoveCall {
        package: Address::from_str(&args.enclave_package_id)
            .context("Failed to parse enclave package ID")?,
        module: Identifier::from_static("enclave"),
        function: Identifier::from_static("register_enclave_secp256k1"),
        type_arguments: vec![TypeTag::from_str(&t_type_str).context("Failed to parse app type")?],
        arguments: vec![Argument::Input(2), Argument::Result(0)],
    };

    // Fetch initial_shared_version of the Enclave config object ID
    let config_owner = provider
        .client
        .ledger_client()
        .get_object(
            GetObjectRequest::const_default()
                .with_object_id(args.enclave_config_id.clone())
                .with_read_mask(FieldMask {
                    paths: vec![
                        "object_id".into(),
                        "owner.version".into(),
                        "owner.kind".into(),
                    ],
                }),
        )
        .await?
        .into_inner()
        .object
        .ok_or_else(|| anyhow!("Failed to retrieve details about the enclave config ID"))?
        .owner
        .ok_or_else(|| anyhow!("Failed to retrieve version details of the enclave config ID"))?;

    // Build the transaction kind
    let tx_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
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
                object_id: Address::from_str(&args.enclave_config_id)
                    .context("Invalid enclave config ID")?,
                initial_shared_version: config_owner.version(),
                mutable: false,
            },
        ],
    });

    let transaction = ChainTransaction::Sui(Box::new(
        sui_adapter
            .kind_to_transaction(
                &mut provider.client,
                tx_kind,
                sender,
                sui_adapter.gas_coin_id,
            )
            .await
            .context("Failed to build the register transaction")?,
    ));

    let _ = sui_adapter
        .send_transaction(false, transaction, &ChainProvider::Sui(provider.clone()))
        .await
        .context("Failed to execute register transaction")?;

    info!("Instance registered successfully!");
    Ok(())
}

async fn fetch_attestation(ip: &str) -> Option<Vec<u8>> {
    let client = Client::new();
    let attestation_url = format!("http://{}:1300/attestation/raw", ip);

    for attempt in 1..=ATTESTATION_RETRIES {
        info!(
            "Fetching attestation (attempt {}/{})",
            attempt, ATTESTATION_RETRIES
        );

        match client.get(&attestation_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => {
                            return Some(bytes.into());
                        }
                        Ok(_) => warn!("Empty attestation response"),
                        Err(e) => error!("Error reading attestation response: {}", e),
                    }
                } else {
                    warn!(
                        "Attestation fetch failed with status: {}",
                        response.status()
                    );
                }
            }
            Err(e) => error!("Failed to connect to attestation endpoint: {}", e),
        }

        info!(
            "Waiting {} seconds before next reachability check...",
            ATTESTATION_INTERVAL
        );
        sleep(Duration::from_secs(ATTESTATION_INTERVAL)).await;
    }

    None
}
