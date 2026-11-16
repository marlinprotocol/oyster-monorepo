mod constants;
mod handlers;
mod provider;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::command;
use clap::Parser;
use diesel::Connection;
use diesel::PgConnection;
use diesel_migrations::MigrationHarness;
use dotenvy::dotenv;
use indexer_framework::{event_loop, start_from, MIGRATIONS};
use provider::AlloyProvider;
use handlers::process_log;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[arg(short, long)]
    rpc: String,

    /// Market contract
    #[arg(short, long)]
    contract: String,

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: u64,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "2000")]
    range_size: u64,
}

fn run() -> Result<()> {
    let args = Args::parse();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    // do not print the url on errors, it has the password
    let mut conn = PgConnection::establish(&database_url).map_err(|e| match e {
        diesel::ConnectionError::InvalidConnectionUrl(_) => {
            anyhow!("failed to connect to the database: invalid DATABASE_URL")
        }
        e => anyhow!("failed to connect to the database: {e}"),
    })?;

    // apply pending migrations
    info!("Applying pending migrations");
    conn.run_pending_migrations(MIGRATIONS)
        // error is not sized, pain to handle the usual way
        .map_err(|e| anyhow!("failed to apply migrations: {e}"))?;
    info!("Applied pending migrations");

    let mut provider = AlloyProvider {
        url: args.rpc.parse()?,
        contract: args.contract.parse()?,
    };
    let is_start_set = start_from(&mut conn, args.start_block)?;
    debug!("is_start_set: {}", is_start_set);
    event_loop(&mut conn, &mut provider, args.range_size, process_log)
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

    // exit with a failure status on errors so that process supervisors restart the indexer
    if let Err(e) = run() {
        error!(?e, "run error");
        std::process::exit(1);
    }

    Ok(())
}
