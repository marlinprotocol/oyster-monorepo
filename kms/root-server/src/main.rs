use std::{future::Future, time::Duration};

use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use kms_derive_utils::{derive_path_seed, to_x25519_secret};
use oyster::axum::{ScallopListener, ScallopState};
use scallop::{AuthStore, AuthStoreState};
use taco::decrypt;
use tokio::{
    fs::{self, read},
    net::TcpListener,
    spawn,
    time::sleep,
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod derive;
mod derive_public;
mod scallop;
mod taco;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to encrypted seed file
    #[arg(long, default_value = "/app/init-params")]
    seed_path: String,

    /// Scallop listening address
    #[arg(long, default_value = "0.0.0.0:1100")]
    scallop_listen_addr: String,

    /// Public listening address
    #[arg(long, default_value = "0.0.0.0:1101")]
    public_listen_addr: String,

    /// Path to file with private key signer
    #[arg(long, default_value = "/app/secp256k1.sec")]
    signer: String,

    /// Porter URI
    #[arg(long, default_value = "https://porter.nucypher.io/decrypt")]
    porter: String,

    /// Ritual id
    #[arg(long, default_value = "40")]
    ritual: u32,

    /// Coordinator address
    #[arg(long, default_value = "0xE74259e3dafe30bAA8700238e324b47aC98FE755")]
    coordinator: String,

    /// RPC URL
    #[arg(long, default_value = "https://polygon-rpc.com")]
    rpc: String,

    /// DKG threshold
    #[arg(long, default_value = "16")]
    threshold: u16,

    /// Initial delay to allow for attestation verification
    #[arg(long, default_value = "1800")]
    delay: u64,
}

#[derive(Clone)]
struct AppState {
    seed: [u8; 64],
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    // sleep to allow attestation verification
    // taco decryption will only work after the signer is
    // verified on chain
    sleep(Duration::from_secs(args.delay)).await;

    let taco_nodes = taco::get_taco_nodes(&args)
        .await
        .context("failed to fetch taco nodes")?;

    let signer = PrivateKeySigner::from_slice(
        &read(&args.signer)
            .await
            .context("failed to read signer file")?,
    )
    .context("failed to create signer")?;

    let chain_id = ProviderBuilder::new()
        .on_http(args.rpc.parse().context("failed to parse rpc url")?)
        .get_chain_id()
        .await
        .context("failed to get chain id")?;

    let encrypted_seed = fs::read(args.seed_path)
        .await
        .context("failed to read seed file")?;
    let seed = decrypt(
        &encrypted_seed,
        args.ritual,
        &taco_nodes,
        args.threshold,
        &args.porter,
        &signer,
        chain_id,
    )
    .await
    .context("failed to decrypt seed")?
    .as_ref()
    .try_into()
    .context("seed is not the right size")?;

    let secret = to_x25519_secret(derive_path_seed(seed, b"oyster.kms.x25519"));

    let scallop_app_state = AppState { seed };
    let public_app_state = scallop_app_state.clone();

    // Panic safety: we simply abort on panics and eschew any handling

    let scallop_handle = spawn(run_forever(move || {
        let app_state = scallop_app_state.clone();
        let listen_addr = args.scallop_listen_addr.clone();
        let secret = secret.clone();
        async move { run_scallop_server(app_state, listen_addr, secret).await }
    }));

    let public_handle = spawn(run_forever(move || {
        let app_state = public_app_state.clone();
        let listen_addr = args.public_listen_addr.clone();
        async move { run_public_server(app_state, listen_addr).await }
    }));

    // should never exit
    tokio::try_join!(scallop_handle, public_handle).expect("not supposed to ever exit");
    panic!("not supposed to ever exit");
}

async fn run_forever<T: FnMut() -> F, F: Future<Output = Result<()>>>(mut task: T) {
    loop {
        if let Err(e) = task().await {
            error!("{e:?}");
        }

        sleep(Duration::from_secs(1)).await;
    }
}

async fn run_scallop_server(
    app_state: AppState,
    listen_addr: String,
    secret: [u8; 32],
) -> Result<()> {
    let auth_store = AuthStore {};

    let app = Router::new()
        .route("/derive", get(derive::derive))
        // middleware is executed bottom to top here
        // we want timeouts to be first, then size checks
        .layer(RequestBodyLimitLayer::new(1024))
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .with_state(app_state);

    let tcp_listener = TcpListener::bind(&listen_addr)
        .await
        .context("failed to bind listener")?;

    let listener = ScallopListener {
        listener: tcp_listener,
        secret,
        auth_store: Some(auth_store),
        auther: None::<()>,
    };

    info!("Listening on {}", listen_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<ScallopState<AuthStoreState>>(),
    )
    .await
    .context("failed to serve")
}

async fn run_public_server(app_state: AppState, listen_addr: String) -> Result<()> {
    let app = Router::new()
        .route(
            "/derive/secp256k1/public",
            get(derive_public::derive_secp256k1_public),
        )
        .route(
            "/derive/secp256k1/address/ethereum",
            get(derive_public::derive_secp256k1_address_ethereum),
        )
        .route(
            "/derive/ed25519/public",
            get(derive_public::derive_ed25519_public),
        )
        .route(
            "/derive/ed25519/address/solana",
            get(derive_public::derive_ed25519_address_solana),
        )
        .route(
            "/derive/x25519/public",
            get(derive_public::derive_x25519_public),
        )
        // middleware is executed bottom to top here
        // we want timeouts to be first, then size checks
        .layer(RequestBodyLimitLayer::new(1024))
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .with_state(app_state);

    let listener = TcpListener::bind(&listen_addr)
        .await
        .context("failed to bind listener")?;

    info!("Listening on {}", listen_addr);
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
