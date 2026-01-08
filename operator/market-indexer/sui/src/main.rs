mod sui;

use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, command};
use dotenvy::dotenv;
use tokio::time::sleep;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::sui::SuiProvider;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// gRPC URL
    #[arg(short, long)]
    grpc_url: String,

    /// gRPC URL auth username
    #[arg(long)]
    grpc_username: Option<String>,

    /// gRPC URL auth password
    #[arg(long)]
    grpc_password: Option<String>,

    /// gRPC URL auth token
    #[arg(long)]
    grpc_token: Option<String>,

    /// Remote checkpoint url
    #[arg(short, long)]
    remote_checkpoint_url: String,

    /// Market program package ID
    #[arg(short, long)]
    package_id: String,

    /// Provider address
    #[arg(long)]
    provider: String,

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: Option<i64>,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "500")]
    range_size: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(
            var.parse()
                .context("Failed to parse the RUST_LOG value set in environment")?,
        );
    }
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_env_filter(filter)
        .init();

    let args = Args::parse();
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

    if args.grpc_username.is_some() && args.grpc_token.is_some() {
        anyhow::bail!("Provide either gRPC username/password OR token, not both");
    }

    let rpc_client = SuiProvider::new(
        args.grpc_url.clone(),
        args.grpc_username,
        args.grpc_password,
        args.grpc_token,
        args.remote_checkpoint_url.clone(),
        args.package_id.clone(),
    )?;

    info!(
        rpc = %args.grpc_url,
        contract = %args.package_id,
        remote_rpc = %args.remote_checkpoint_url,
        provider = %args.provider,
        start_block = ?args.start_block,
        range_size = args.range_size,
        "Starting Sui indexer"
    );

    loop {
        let res = indexer_framework::run(
            database_url.clone(),
            rpc_client.clone(),
            args.provider.clone(),
            args.start_block,
            args.range_size,
        )
        .await;

        if let Err(e) = res {
            error!(error = ?e, "Indexer error, retrying after delay");
            sleep(Duration::from_secs(30)).await;
        } else {
            warn!("Indexer returned unexpectedly, restarting");
            sleep(Duration::from_secs(5)).await;
        }
    }
}
