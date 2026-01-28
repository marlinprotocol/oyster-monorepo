mod constants;
mod handlers;
mod provider;

use anyhow::Result;
use clap::command;
use clap::Parser;
use diesel::Connection;
use diesel::PgConnection;
use diesel_migrations::MigrationHarness;
use dotenvy::dotenv;
use handlers::handle_log;
use indexer_framework::{event_loop, start_from, MIGRATIONS};
use provider::SuiProvider;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: u64,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "500")]
    range_size: u64,
}

fn run() -> Result<()> {
    let args = Args::parse();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut conn = PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url));

    // apply pending migrations
    info!("Applying pending migrations");
    conn.run_pending_migrations(MIGRATIONS)
        // error is not sized, pain to handle the usual way
        .expect("failed to apply migrations");
    info!("Applied pending migrations");

    let mut provider = SuiProvider::new(
        args.remote_checkpoint_url,
        args.grpc_url,
        args.grpc_username,
        args.grpc_password,
        args.grpc_token,
        args.package_id,
    )?;

    let is_start_set = start_from(&mut conn, args.start_block)?;
    debug!("is_start_set: {}", is_start_set);
    event_loop(&mut conn, &mut provider, args.range_size, handle_log)
}

fn main() -> Result<()> {
    dotenv().ok();

    // seems messy, see if there is a better way
    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
