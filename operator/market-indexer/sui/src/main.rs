mod sui;

use anyhow::{Context, Result};
use clap::{Parser, command};
use dotenvy::dotenv;
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

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let rpc_client = SuiProvider {
        remote_checkpoint_url: args.remote_checkpoint_url,
        grpc_url: args.grpc_url,
        rpc_username: args.grpc_username,
        rpc_password: args.grpc_password,
        package_id: args.package_id,
    };

    indexer_framework::run(
        database_url,
        rpc_client,
        args.provider,
        args.start_block,
        args.range_size,
    )
    .await
    .context("Indexer run error")
}
