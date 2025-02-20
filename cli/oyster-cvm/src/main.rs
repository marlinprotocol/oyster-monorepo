use anyhow::Result;
use clap::{Parser, Subcommand};
use oyster::attestation::AWS_ROOT_KEY;

mod args;
mod commands;
mod types;
mod utils;

use crate::args::pcr::PcrArgs;
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

        /// Operator address
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

        /// Disable automatic log streaming in debug mode
        #[arg(long, requires = "debug")]
        no_stream: bool,

        /// Init params, base64 encoded
        #[arg(long, default_value = "")]
        init_params: String,

        /// Extra init params, base64 encoded
        #[arg(long, default_value = "")]
        extra_init_params: String,
    },
    /// Verify Oyster Enclave Attestation
    Verify {
        /// Enclave IP
        #[arg(short = 'e', long, required = true)]
        enclave_ip: String,

        #[command(flatten)]
        pcr: PcrArgs,

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
        #[arg(short = 'r', long, default_value_t = hex::encode(AWS_ROOT_KEY))]
        root_public_key: String,
    },
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

    let result = match &cli.command {
        Commands::Doctor => commands::doctor::run_doctor(),
        Commands::Build {
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
        Commands::Verify {
            pcr,
            enclave_ip,
            attestation_port,
            max_age,
            root_public_key,
            timestamp,
        } => {
            commands::verify::verify_enclave(
                pcr,
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
            no_stream,
            init_params,
            extra_init_params,
        } => {
            let config = DeploymentConfig {
                image_url: image_url.clone(),
                region: region.clone(),
                instance_type: instance_type.clone(),
                bandwidth: *bandwidth,
                duration: *duration_in_minutes,
                job_name: job_name.clone(),
                debug: *debug,
                no_stream: *no_stream,
                init_params: init_params.clone(),
                extra_init_params: extra_init_params.clone(),
            };
            commands::deploy::deploy_oyster_instance(config, wallet_private_key, operator).await
        }
        Commands::Update {
            job_id,
            wallet_private_key,
            image_url,
            debug,
        } => {
            commands::update::update_job(
                job_id,
                wallet_private_key,
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
        } => commands::log::stream_logs(ip, start_from.as_deref(), *with_log_id, *quiet).await,
    };

    if let Err(err) = &result {
        tracing::error!("Error: {:#}", err);
        std::process::exit(1);
    }

    Ok(())
}
