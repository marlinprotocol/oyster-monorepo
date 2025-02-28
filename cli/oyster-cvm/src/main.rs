use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{deploy::DeployArgs, verify::VerifyArgs};

mod args;
mod commands;
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
#[command(about = "Oyster CVM command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check environment dependencies including Docker & Nix
    Doctor {
        /// Perform Docker checks
        #[arg(short, long)]
        docker: bool,
        /// Perform Nix checks
        #[arg(short, long)]
        nix: bool,
    },
    /// Build Oyster CVM Image
    Build {
        /// Platform (amd64 or arm64)
        #[arg(short, long, value_parser = [types::Platform::AMD64.as_str(), types::Platform::ARM64.as_str()])]
        platform: String,

        /// Path to docker-compose.yml file
        #[arg(short = 'c', long)]
        docker_compose: String,

        /// List of Docker image .tar file paths
        #[arg(short = 'i', long, default_value = "")]
        docker_images: Vec<String>,

        /// Output folder name
        #[arg(short, long, default_value = "result")]
        output: String,

        /// Git commit reference for oyster-monorepo
        #[arg(
            short = 'r',
            long,
            default_value = "oyster-cvm-v1.1.0" // To be updated when new version is tagged
        )]
        commit_ref: String,
    },
    /// Upload Enclave Image to IPFS
    Upload {
        /// Path to enclave image file
        #[arg(short, long)]
        file: String,
    },
    /// Deploy an Oyster CVM instance
    Deploy(DeployArgs),
    /// Verify Oyster Enclave Attestation
    Verify(VerifyArgs),
    /// Update existing deployments
    Update {
        /// Job ID
        #[arg(short, long)]
        job_id: String,

        /// Wallet private key for transaction signing
        #[arg(long)]
        wallet_private_key: String,

        /// New URL of the enclave image
        #[arg(short, long)]
        image_url: Option<String>,

        /// New debug mode
        #[arg(short, long)]
        debug: Option<bool>,
    },
    /// Stream logs from an Oyster CVM instance
    Logs {
        /// IP address of the instance
        #[arg(short, long, required = true)]
        ip: String,

        /// Optional log ID to start streaming from
        #[arg(short, long)]
        start_from: Option<String>,

        /// Include log ID prefix in output
        #[arg(short, long, default_value_t = false)]
        with_log_id: bool,

        /// Suppress connection status message
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Doctor { docker, nix } => {
            // enable all if nothing is enabled
            let all = !docker && !nix;
            commands::doctor::run_doctor(docker || all, nix || all)
        }
        Commands::Build {
            platform,
            docker_compose,
            docker_images,
            output,
            commit_ref,
        } => {
            let platform = types::Platform::from_str(&platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_oyster_image(
                platform,
                &docker_compose,
                &docker_images,
                &output,
                &commit_ref,
            )
        }
        Commands::Upload { file } => {
            let default_provider = types::StorageProvider::Pinata;
            commands::upload::upload_enclave_image(&file, &default_provider).await
        }
        Commands::Verify(args) => commands::verify::verify(args).await,
        Commands::Deploy(args) => commands::deploy::deploy(args).await,
        Commands::Update {
            job_id,
            wallet_private_key,
            image_url,
            debug,
        } => {
            commands::update::update_job(
                &job_id,
                &wallet_private_key,
                image_url.as_ref().map(|x| x.as_str()),
                debug.to_owned(),
            )
            .await
        }
        Commands::Logs {
            ip,
            start_from,
            with_log_id,
            quiet,
        } => commands::log::stream_logs(&ip, start_from.as_deref(), with_log_id, quiet).await,
    };

    if let Err(err) = &result {
        tracing::error!("Error: {:#}", err);
        std::process::exit(1);
    }

    Ok(())
}
