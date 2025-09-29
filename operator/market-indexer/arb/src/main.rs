mod arb;

use anyhow::{Context, Result};
use clap::{command, Parser};
use dotenvy::dotenv;
use indexer_framework::repository::Repository;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

use arb::ArbProvider;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[arg(short, long)]
    rpc: String,

    /// Market contract address
    #[arg(short, long)]
    contract: String,

    /// Provider address
    #[arg(short, long)]
    provider: String,

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: Option<i64>,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "500")]
    range_size: u64,
}

async fn run() -> Result<()> {
    let args = Args::parse();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let provider = ArbProvider {
        rpc_url: args.rpc.parse()?,
        contract: args.contract.parse()?,
        provider: args.provider.parse()?,
    };

    let repository = Repository::new(database_url).await?;

    indexer_framework::run(repository, provider, args.start_block, args.range_size).await
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_env_filter(filter)
        .init();

    run().await.context("run error")
}
