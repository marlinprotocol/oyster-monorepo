use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{
    build::BuildArgs, deploy::DeployArgs, deposit::DepositArgs, derive::KmsDeriveArgs,
    doctor::DoctorArgs, image_id::ImageArgs, kms_contract::KmsContractArgs, list::ListArgs,
    log::LogArgs, simulate::SimulateArgs, stop::StopArgs, update::UpdateArgs, upload::UploadArgs,
    verify::VerifyArgs, withdraw::WithdrawArgs,
};

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
#[command(version, about = "Oyster CVM command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Doctor(DoctorArgs),
    Simulate(SimulateArgs),
    Build(BuildArgs),
    Upload(UploadArgs),
    Deploy(DeployArgs),
    Verify(VerifyArgs),
    List(ListArgs),
    Update(UpdateArgs),
    Logs(LogArgs),
    Deposit(DepositArgs),
    Stop(StopArgs),
    Withdraw(WithdrawArgs),
    ComputeImageId(ImageArgs),
    KmsDerive(KmsDeriveArgs),
    KmsContract(KmsContractArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Doctor(args) => commands::doctor::run_doctor(args),
        Commands::Simulate(args) => commands::simulate::simulate(args).await,
        Commands::Build(args) => commands::build::build_oyster_image(args),
        Commands::Upload(args) => commands::upload::upload_enclave_image(args).await,
        Commands::Verify(args) => commands::verify::verify(args).await,
        Commands::Deploy(args) => commands::deploy::deploy(args).await,
        Commands::List(args) => commands::list::list_jobs(args).await,
        Commands::Update(args) => commands::update::update_job(args).await,
        Commands::Logs(args) => commands::log::stream_logs(args).await,
        Commands::Deposit(args) => commands::deposit::deposit_to_job(args).await,
        Commands::Stop(args) => commands::stop::stop_oyster_instance(args).await,
        Commands::Withdraw(args) => commands::withdraw::withdraw_from_job(args).await,
        Commands::ComputeImageId(args) => commands::image_id::compute_image_id(args),
        Commands::KmsDerive(args) => commands::derive::kms_derive(args).await,
        Commands::KmsContract(args) => commands::kms_contract::kms_contract(args).await,
    };

    if let Err(e) = result {
        tracing::error!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
