use anyhow::{anyhow, Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use fetch::fetch_seed;
use scallop::{AuthStore, Auther};
use tokio::{
    fs::{read, read_to_string},
    net::TcpListener,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod fetch;
mod scallop;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// KMS endpoint
    #[arg(
        long,
        conflicts_with = "root_server_config",
        required_unless_present = "root_server_config"
    )]
    kms_endpoint: Option<String>,

    /// Listening address
    #[arg(long, default_value = "127.0.0.1:1100")]
    listen_addr: String,

    /// Attestation endpoint
    #[arg(long, default_value = "http://127.0.0.1:1301/attestation/raw")]
    attestation_endpoint: String,

    /// Path to X25519 secret file
    #[arg(long, default_value = "/app/x25519.sec")]
    secret_path: String,

    /// PCR0 of the root server
    #[arg(
        long,
        conflicts_with = "root_server_config",
        required_unless_present = "root_server_config"
    )]
    pcr0: Option<String>,

    /// PCR1 of the root server
    #[arg(
        long,
        conflicts_with = "root_server_config",
        required_unless_present = "root_server_config"
    )]
    pcr1: Option<String>,

    /// PCR2 of the root server
    #[arg(
        long,
        conflicts_with = "root_server_config",
        required_unless_present = "root_server_config"
    )]
    pcr2: Option<String>,

    /// user data of the root server
    #[arg(
        long,
        conflicts_with = "root_server_config",
        required_unless_present = "root_server_config"
    )]
    user_data: Option<String>,

    /// file containing enclave verification contract address in hexadecimal
    #[arg(long)]
    contract_address_file: Option<String>,

    /// JSON config file containing the root server's details
    #[arg(long, required_unless_present_all = ["kms_endpoint", "pcr0", "pcr1", "pcr2", "user_data"])]
    root_server_config: Option<String>,
}

#[derive(Clone)]
struct AppState {
    seed: [u8; 64],
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    let secret: [u8; 32] = read(args.secret_path)
        .await
        .context("failed to read secret file")?
        .try_into()
        .map_err(|_| anyhow!("failed to parse secret file"))?;

    let auther = Auther {
        url: args.attestation_endpoint,
    };

    let pcr0: [u8; 48];
    let pcr1: [u8; 48];
    let pcr2: [u8; 48];
    let user_data: Box<[u8]>;
    let kms_endpoint: String;

    if let Some(filename) = args.root_server_config {
        let config_content = read_to_string(filename)
            .await
            .context("failed to read root server config file")?;
        let config: serde_json::Value = serde_json::from_str(&config_content)
            .context("failed to parse root server config file")?;

        kms_endpoint = config["kms_endpoint"]
            .as_str()
            .context("missing kms_endpoint in config")?
            .to_string();
        pcr0 = hex::decode(config["pcr0"].as_str().context("missing pcr0 in config")?)
            .context("failed to decode pcr0")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr0 size"))?;
        pcr1 = hex::decode(config["pcr1"].as_str().context("missing pcr1 in config")?)
            .context("failed to decode pcr1")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr1 size"))?;
        pcr2 = hex::decode(config["pcr2"].as_str().context("missing pcr2 in config")?)
            .context("failed to decode pcr2")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr2 size"))?;
        user_data = hex::decode(
            config["user_data"]
                .as_str()
                .context("missing user_data in config")?,
        )
        .context("failed to decode user data")?
        .into_boxed_slice();
    } else {
        kms_endpoint = args.kms_endpoint.unwrap();
        pcr0 = hex::decode(args.pcr0.unwrap())
            .context("failed to decode pcr0")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr0 size"))?;
        pcr1 = hex::decode(args.pcr1.unwrap())
            .context("failed to decode pcr1")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr1 size"))?;
        pcr2 = hex::decode(args.pcr2.unwrap())
            .context("failed to decode pcr2")?
            .try_into()
            .map_err(|_| anyhow!("incorrect pcr2 size"))?;
        user_data = hex::decode(args.user_data.unwrap())
            .context("failed to decode user data")?
            .into_boxed_slice();
    }

    let auth_store = AuthStore {
        state: ([pcr0, pcr1, pcr2], user_data),
    };

    let contract_address = if let Some(contract_address_file) = args.contract_address_file {
        let address = read(contract_address_file)
            .await
            .context("failed to read contract address file")?;
        Some(
            String::from_utf8(address)
                .context("failed to parse contract address")?
                .trim()
                .to_string(),
        )
    } else {
        None
    };

    let seed = fetch_seed(auther, auth_store, secret, kms_endpoint, contract_address)
        .await
        .context("failed to fetch seed")?;

    let app_state = AppState { seed };

    let app = Router::new()
        .route("/derive", get(derive::derive))
        .route("/derive/secp256k1", get(derive::derive_secp256k1))
        .route("/derive/ed25519", get(derive::derive_ed25519))
        .route("/derive/x25519", get(derive::derive_x25519))
        .with_state(app_state);

    let listener = TcpListener::bind(&args.listen_addr)
        .await
        .context("failed to bind listener")?;

    info!("Listening on {}", args.listen_addr);
    axum::serve(listener, app).await.context("failed to serve")
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
