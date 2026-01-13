mod sui;

use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, command};
use dotenvy::dotenv;
use indexer_framework::SaturatingConvert;
use indexer_framework::health::{HealthConfig, HealthTracker, start_health_server};
use tokio::time::sleep;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::sui::SuiProvider;

const STARTUP_GRACE_SECS: u64 = 300;
const UNHEALTHY_CONSECUTIVE_ERRORS: u64 = 5;
const DEGRADED_CONSECUTIVE_ERRORS: u64 = 3;
const UNHEALTHY_ERROR_RATE: f64 = 0.40;
const DEGRADED_ERROR_RATE: f64 = 0.20;
const UNHEALTHY_STALE_SECS: u64 = 180;
const DEGRADED_STALE_SECS: u64 = 60;
const UNHEALTHY_LAG_WINDOW: i64 = 3;
const DEGRADED_LAG_WINDOW: i64 = 2;

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

    /// Health check port
    #[arg(long, default_value = "8080")]
    health_port: u16,
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

    let health = HealthTracker::new(HealthConfig {
        startup_grace: Duration::from_secs(STARTUP_GRACE_SECS),
        unhealthy_consecutive_errors: UNHEALTHY_CONSECUTIVE_ERRORS,
        degraded_consecutive_errors: DEGRADED_CONSECUTIVE_ERRORS,
        unhealthy_error_rate: UNHEALTHY_ERROR_RATE,
        degraded_error_rate: DEGRADED_ERROR_RATE,
        unhealthy_stale: Duration::from_secs(UNHEALTHY_STALE_SECS),
        degraded_stale: Duration::from_secs(DEGRADED_STALE_SECS),
        unhealthy_lag: args.range_size.saturating_to() * UNHEALTHY_LAG_WINDOW,
        degraded_lag: args.range_size.saturating_to() * DEGRADED_LAG_WINDOW,
    });
    let health_clone = health.clone();
    let health_port = args.health_port;

    tokio::spawn(async move {
        loop {
            if let Err(e) = start_health_server(health_clone.clone(), health_port).await {
                error!(error = ?e, "Health server crashed, restarting in 5s");
                sleep(Duration::from_secs(5)).await;
            } else {
                warn!("Health server exited, restarting in 5s");
                sleep(Duration::from_secs(5)).await;
            }
        }
    });

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
        info!("Starting indexer run");

        let res = indexer_framework::run(
            database_url.clone(),
            rpc_client.clone(),
            args.provider.clone(),
            args.start_block,
            args.range_size,
            health.clone(),
        )
        .await;

        if let Err(e) = res {
            error!(error = ?e, "Indexer error, retrying after delay");
            sleep(Duration::from_secs(30)).await;
        } else {
            warn!("Indexer returned unexpectedly (no error), restarting in 5s");
            health.record_error("indexer_run_failed_unexpectedly");
            sleep(Duration::from_secs(5)).await;
        }
    }
}
