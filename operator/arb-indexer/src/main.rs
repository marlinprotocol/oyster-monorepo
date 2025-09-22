mod arb_client;
mod indexer;
mod repository;
mod schema;

use std::path::Path;

use anyhow::{Context, Result};
use clap::{command, Parser};
use dotenvy::dotenv;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use crate::arb_client::RpcProvider;
use crate::repository::Repository;

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

const MIGRATION_PATH: &str = "./migrations";

async fn run() -> Result<()> {
    let args = Args::parse();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create an async connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to the DATABASE_URL")?;

    // Apply pending migrations asynchronously
    info!("Applying pending migrations");
    let migrator = Migrator::new(Path::new(MIGRATION_PATH))
        .await
        .context("Failed to initialize the migrator")?;
    migrator
        .run(&pool)
        .await
        .context("Failed to apply migrations to the database")?;
    info!("Applied pending migrations");

    let provider = RpcProvider {
        url: args.rpc.parse()?,
        contract: args.contract.parse()?,
        provider: args.provider.parse()?,
    };

    let repository = Repository::new(pool);

    if args.start_block.is_some() {
        let mut tx = repository
            .pool
            .begin()
            .await
            .context("Failed to begin a transaction for start_block update")?;
        let updated = repository
            .update_state(&mut tx, args.start_block.unwrap())
            .await
            .context("Failed to update the start_block in the DB")?;
        tx.commit()
            .await
            .context("Failed to commit the update start_block transaction")?;

        debug!("is_start_set: {}", updated == 1);
    }

    indexer::run(repository, provider, args.range_size).await
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    run().await.context("run error")
}
