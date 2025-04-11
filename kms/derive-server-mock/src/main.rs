use anyhow::{Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Listening address
    #[arg(long, default_value = "127.0.0.1:1100")]
    listen_addr: String,
}

#[derive(Clone)]
struct AppState {
    seed: [u8; 64],
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    let args = Args::parse();

    let seed = [0u8; 64]; // Constant seed

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
