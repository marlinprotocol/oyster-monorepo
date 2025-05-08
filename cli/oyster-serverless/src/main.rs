use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::deploy::DeployArgs;
use commands::dev::DevArgs;
use commands::doctor::DoctorArgs;
use commands::job::JobArgs;
use commands::new_project::NewArgs;
use commands::subscription::SubscriptionArgs;

mod args;
mod commands;
mod configs;
mod types;
mod utils;

use tracing_subscriber::EnvFilter;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

#[derive(Parser)]
#[command(version, about = "Oyster Serverless command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check optional system dependencies like Docker
    Doctor(DoctorArgs),
    /// Create a new project
    New(NewArgs),
    /// Start development server
    Dev(DevArgs),
    /// Deploy code to contract
    Deploy(DeployArgs),
    /// Handle oyster serverless jobs
    Job(JobArgs),
    /// Handle oyster serverless subscriptions
    Subscription(SubscriptionArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Doctor(args) => commands::doctor::run_doctor(args),
        Commands::New(args) => commands::new_project::run_new(args).await,
        Commands::Dev(args) => commands::dev::run_dev(args).await,
        Commands::Deploy(args) => commands::deploy::run_deploy(args).await,
        Commands::Job(args) => commands::job::run_job(args).await,
        Commands::Subscription(args) => commands::subscription::run_subscription(args).await,
    };

    if let Err(e) = result {
        tracing::error!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
