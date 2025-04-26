use crate::types::Platform;
use anyhow::{Context, Result};
use clap::Args;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use tracing::info;

/// Build enclave image
#[derive(Args)]
pub struct BuildArgs {
    /// Platform (amd64 or arm64)
    #[arg(short, long)]
    platform: Platform,

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
}

pub fn build_oyster_image(args: BuildArgs) -> Result<()> {
    info!("Building oyster-cvm image with:");
    info!("  Platform: {}", args.platform.as_str());
    info!("  Docker compose: {}", args.docker_compose);
    info!("  Commit ref: {}", args.commit_ref);

    let platform = args.platform;

    let docker_images_list = args.docker_images.join(" ");
    if !docker_images_list.is_empty() {
        info!("  Docker images: {}", docker_images_list);
    }

    let nix_expr = format!(
        r#"((builtins.getFlake "github:marlinprotocol/oyster-monorepo/{}").packages.{}.musl.sdks.docker-enclave.override {{compose={};dockerImages=[{}];}}).default"#,
        args.commit_ref,
        platform.nix_arch(),
        args.docker_compose,
        docker_images_list
    );

    // TODO: Have to explicitly fill in the cache here to make it work
    // See if there is a better way
    let mut cmd = Command::new("nix")
        .args([
            "build",
            "--impure",
            "--option",
            "substituters",
            "https://cache.nixos.org https://oyster.cachix.org",
            "--option",
            "trusted-public-keys",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY=",
            "--system",
            platform.nix_arch(),
            "--expr",
            &nix_expr,
            "-vL",
            "--out-link",
            &args.output,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to execute Nix build command")?;

    let stdout = cmd.stdout.take().unwrap();
    let stdout_reader = BufReader::new(stdout);

    // Stream nix output through tracing with .context()?
    for line_result in stdout_reader.lines() {
        let line = line_result.context("Failed to read line from stdout")?;
        info!(target: "nix", "{}", line);
    }

    info!("Build finished");

    Ok(())
}
