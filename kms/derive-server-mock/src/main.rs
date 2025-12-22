use std::fs;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use blake2::{Blake2b512, Digest};
use clap::Parser;
use serde_yaml::Value;
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

    /// Flag to enable contract based derive server behavior (constant seed)
    #[arg(long)]
    contract: bool,

    /// Path to docker-compose file for yaml based seed
    #[arg(long, conflicts_with = "contract")]
    docker_compose: Option<String>,
}

#[derive(Clone)]
struct AppState {
    seed: [u8; 64],
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    let args = Args::parse();

    let mut seed = [0u8; 64];
    if !args.contract {
        seed = deterministic_seed_from_docker_compose(&args.docker_compose.unwrap())?;
    }

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

fn deterministic_seed_from_docker_compose(path: &str) -> Result<[u8; 64]> {
    let content = fs::read_to_string(path).context("Failed to read docker compose file")?;
    let yaml: Value = serde_yaml::from_str(&content).context("Invalid docker compose yaml")?;
    let canonical = serde_yaml::to_string(&yaml).context("Failed to serialize yaml file")?;

    let mut hasher = Blake2b512::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();

    let mut seed = [0u8; 64];
    seed.copy_from_slice(&hash);
    Ok(seed)
}
