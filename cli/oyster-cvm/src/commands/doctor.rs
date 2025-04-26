use crate::types::Dependency;
use anyhow::Result;
use clap::Args;
use std::process::Command;
use tracing::{error, info};

/// Check optional system dependencies like Docker & Nix
#[derive(Args)]
pub struct DoctorArgs {
    /// Perform Docker checks
    #[arg(short, long)]
    docker: bool,
    /// Perform Nix checks
    #[arg(short, long)]
    nix: bool,
}

pub fn run_doctor(args: DoctorArgs) -> Result<()> {
    // enable all if nothing is enabled
    let all = !args.docker && !args.nix;

    let docker = args.docker || all;
    let nix = args.nix || all;

    let mut has_error = false;
    let mut error_msg = String::new();

    if docker {
        // Check Docker
        if let Err(e) = check_dependency(Dependency::Docker) {
            has_error = true;
            error_msg.push_str(&format!("{}\n", e));
        }
    }

    if nix {
        // Check Nix
        if let Err(e) = check_dependency(Dependency::Nix) {
            has_error = true;
            error_msg.push_str(&format!("{}\n", e));
            error_msg.push_str("Additional Nix checks skipped till Nix check is healthy.\n");
        } else {
            // Additinal Nix checks, only if Nix is found

            // Check Nix trusted user
            if let Err(e) = check_nix_trusted_user() {
                has_error = true;
                error_msg.push_str(&format!("{}\n", e));
            }

            // Check Nix experimental features
            if let Err(e) = check_nix_experimental_features() {
                has_error = true;
                error_msg.push_str(&format!("{}\n", e));
            }
        }
    }

    if has_error {
        Err(anyhow::anyhow!(error_msg.trim().to_string()))
    } else {
        Ok(())
    }
}

fn check_dependency(dep: Dependency) -> Result<()> {
    if Command::new(dep.command())
        .arg("--version")
        .output()
        .is_err()
    {
        error!(
            "{} is not installed. Please install it from {} and try again",
            dep.name(),
            dep.install_url()
        );
        return Err(anyhow::anyhow!("{} is required but not found", dep.name()));
    } else {
        info!("{} is installed ✓", dep.name());
    }
    Ok(())
}

fn check_nix_trusted_user() -> Result<()> {
    let output = Command::new("nix")
        .args(["config", "show", "trusted-users"])
        .output()
        .map_err(|_| anyhow::anyhow!("Failed to get nix trusted users"))?;

    if !output.status.success() {
        error!("Failed to get nix trusted users");
        return Err(anyhow::anyhow!("Failed to get nix trusted users"));
    }

    let trusted_users = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("Failed to parse nix trusted users output"))?;

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map_err(|_| anyhow::anyhow!("Failed to get current username"))?;

    if !trusted_users.contains(&username) {
        error!(
            "Current user '{}' is not in nix trusted-users. To fix this:\n\
            1. Edit /etc/nix/nix.conf with sudo:\n\
               $ sudo nano /etc/nix/nix.conf\n\
            2. Add your username to trusted-users line (create if doesn't exist):\n\
               trusted-users = root {}\n\
            3. Restart nix-daemon:\n\
               $ sudo systemctl restart nix-daemon",
            username, username
        );
        return Err(anyhow::anyhow!("Nix trusted-users check failed"));
    }

    info!("Current user is in nix trusted-users list ✓");
    Ok(())
}

fn check_nix_experimental_features() -> Result<()> {
    let output = Command::new("nix")
        .args(["config", "show", "experimental-features"])
        .output()
        .map_err(|_| anyhow::anyhow!("Failed to get nix experimental features"))?;

    if !output.status.success() {
        error!("Failed to get nix experimental features");
        return Err(anyhow::anyhow!("Failed to get nix experimental features"));
    }

    let features = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("Failed to parse nix experimental features output"))?;

    if !features.contains("nix-command") || !features.contains("flakes") {
        error!(
            "Required Nix experimental features are not enabled. To fix this:\n\
            1. Edit /etc/nix/nix.conf with sudo:\n\
               $ sudo nano /etc/nix/nix.conf\n\
            2. Add or modify experimental-features line:\n\
               experimental-features = nix-command flakes\n\
            3. Restart nix-daemon:\n\
               $ sudo systemctl restart nix-daemon"
        );
        return Err(anyhow::anyhow!(
            "Missing required Nix experimental features (nix-command and flakes)"
        ));
    }

    info!("Nix experimental features (nix-command and flakes) are enabled ✓");
    Ok(())
}
