use anyhow::Result;
use clap::{Parser, Subcommand, ArgGroup};

mod commands;
mod types;
mod utils;

use crate::commands::deploy::DeploymentConfig;
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
    Doctor,
    /// Build Oyster CVM Image
    BuildImage {
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
            default_value = "3e6dbc844b42281462e65d7742d9436d4205fcfd" // To be updated when nix configs are changed
        )]
        commit_ref: String,
    },
    /// Upload Enclave Image to IPFS
    Upload {
        /// Path to enclave image file
        #[arg(short, long)]
        file: String,
    },
    /// Verify Oyster Enclave Attestation
    #[command(
        about = "Verify Oyster Enclave Attestation",
        group = ArgGroup::new("pcr_source")
            .args(["pcr_file", "pcr0"])
            .required(true), // One of these groups is required
    )]
    VerifyEnclave {
        /// Enclave IP
        #[arg(short = 'e', long, required = true)]
        enclave_ip: String,

        /// Path to PCRs JSON file
        #[arg(long, default_value = "", conflicts_with_all(["pcr0", "pcr1", "pcr2"]))]
        pcr_file: String,

        /// PCR 0
        #[arg(short = '0', default_value = "", long, requires_all(["pcr1", "pcr2"]))]
        pcr0: String,

        /// PCR 1
        #[arg(short = '1', default_value = "", long, requires_all(["pcr0", "pcr2"]))]
        pcr1: String,

        /// PCR 2
        #[arg(short = '2', default_value = "", long, requires_all(["pcr0", "pcr1"]))]
        pcr2: String,

        /// Attestation Port (default: 1300)
        #[arg(short = 'p', long, default_value = "1300")]
        attestation_port: u16,

        /// Maximum age of attestation (in milliseconds) (default: 300000)
        #[arg(short = 'a', long, default_value = "300000")]
        max_age: usize,

        /// Attestation timestamp (in milliseconds)
        #[arg(short = 't', long, default_value = "0")]
        timestamp: usize,

        /// Root public key
        #[arg(short = 'r', long, default_value = "")]
        root_public_key: String,
    },
    /// Deploy an Oyster CVM instance
    Deploy {
        /// URL of the enclave image
        #[arg(long, required = true)]
        image_url: String,

        /// Region for deployment
        #[arg(long, required = true)]
        region: String,

        /// Wallet private key for transaction signing
        #[arg(long, required = true)]
        wallet_private_key: String,

        /// Optional operator address
        #[arg(long, required = true)]
        operator: String,

        /// Instance type (e.g. "m5a.2xlarge")
        #[arg(long, required = true)]
        instance_type: String,

        /// Optional bandwidth in KBps (default: 10)
        #[arg(long, default_value = "10")]
        bandwidth: u32,

        /// Duration in minutes
        #[arg(long, required = true)]
        duration_in_minutes: u32,

        /// Job name
        #[arg(long, default_value = "")]
        job_name: String,

        /// Enable debug mode
        #[arg(long)]
        debug: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Doctor => commands::doctor::run_doctor(),
        Commands::BuildImage {
            platform,
            docker_compose,
            docker_images,
            output,
            commit_ref,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_oyster_image(
                platform,
                docker_compose,
                docker_images,
                output,
                commit_ref,
            )
        }
        Commands::Upload { file } => {
            let default_provider = types::StorageProvider::Pinata;
            commands::upload::upload_enclave_image(file, &default_provider).await
        }
        Commands::VerifyEnclave {
            pcr0,
            pcr1,
            pcr2,
            enclave_ip,
            attestation_port,
            max_age,
            root_public_key,
            timestamp,
            pcr_file,
        } => {
            commands::verify::verify_enclave(
                pcr_file,
                pcr0,
                pcr1,
                pcr2,
                enclave_ip,
                attestation_port,
                max_age,
                root_public_key,
                timestamp,
            )
            .await
        }
        Commands::Deploy {
            image_url,
            region,
            wallet_private_key,
            operator,
            instance_type,
            bandwidth,
            duration_in_minutes,
            job_name,
            debug,
        } => {
            let config = DeploymentConfig {
                image_url: image_url.clone(),
                region: region.clone(),
                instance_type: instance_type.clone(),
                bandwidth: *bandwidth,
                duration: *duration_in_minutes,
                job_name: job_name.clone(),
                debug: *debug,
            };
            commands::deploy::deploy_oyster_instance(config, wallet_private_key, operator).await
        }
    };

    if let Err(err) = &result {
        tracing::error!("Error: {:#}", err);
        std::process::exit(1);
    }

    Ok(())
}
