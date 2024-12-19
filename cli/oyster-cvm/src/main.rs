use anyhow::Result;
use clap::{Parser, Subcommand};
mod commands;
mod types;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .with_file(false)
        .with_line_number(false)
        .init();
}

#[derive(Parser)]
#[command(about = "AWS Nitro Enclave Image Builder")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check environment dependencies including Docker & Nix
    Doctor,
    /// Build Enclave Image
    BuildImage {
        /// Platform (amd64 or arm64)
        #[arg(short, long, value_parser = [types::Platform::AMD64.as_str(), types::Platform::ARM64.as_str()])]
        platform: String,

        /// Path to docker-compose.yml file
        #[arg(short = 'c', long)]
        docker_compose: String,

        /// List of Docker image .tar file paths
        #[arg(short = 'i', long, required = true)]
        docker_images: Vec<String>,

        /// Output folder name
        #[arg(short, long, default_value = "result")]
        output: String,
    },
    /// Upload Enclave Image to IPFS
    Upload {
        /// Path to enclave image file
        #[arg(short, long)]
        file: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Doctor => commands::doctor::run_doctor()?,
        Commands::BuildImage {
            platform,
            docker_compose,
            docker_images,
            output,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_enclave_image(platform, docker_compose, docker_images, output)?
        }
        Commands::Upload { file } => {
            let default_provider = types::StorageProvider::Pinata;
            commands::upload::upload_enclave_image(file, &default_provider).await?;
        }
    }

    Ok(())
}
