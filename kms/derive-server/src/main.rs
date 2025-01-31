use anyhow::{anyhow, Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use fetch::fetch_randomness;
use scallop::{AuthStore, Auther};
use tokio::{fs::read, net::TcpListener};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod fetch;
mod scallop;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// KMS endpoint
    #[arg(long)]
    kms_endpoint: String,

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
    #[arg(long)]
    pcr0: String,

    /// PCR1 of the root server
    #[arg(long)]
    pcr1: String,

    /// PCR2 of the root server
    #[arg(long)]
    pcr2: String,

    /// user data of the root server
    #[arg(long)]
    user_data: String,
}

#[derive(Clone)]
struct AppState {
    randomness: [u8; 64],
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

    let pcr0: [u8; 48] = hex::decode(args.pcr0)
        .context("failed to decode pcr0")?
        .try_into()
        .map_err(|_| anyhow!("incorrect pcr0 size"))?;
    let pcr1: [u8; 48] = hex::decode(args.pcr1)
        .context("failed to decode pcr1")?
        .try_into()
        .map_err(|_| anyhow!("incorrect pcr1 size"))?;
    let pcr2: [u8; 48] = hex::decode(args.pcr2)
        .context("failed to decode pcr2")?
        .try_into()
        .map_err(|_| anyhow!("incorrect pcr2 size"))?;
    let user_data = hex::decode(args.user_data)
        .context("failed to decode user data")?
        .into_boxed_slice();

    let auth_store = AuthStore {
        state: ([pcr0, pcr1, pcr2], user_data),
    };

    let randomness = fetch_randomness(auther, auth_store, secret, args.kms_endpoint)
        .await
        .context("failed to fetch randomness")?;

    let app_state = AppState { randomness };

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
