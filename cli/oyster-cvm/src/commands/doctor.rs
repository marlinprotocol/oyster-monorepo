use crate::types::Dependency;
use anyhow::Result;
use tracing::{error, info};
use std::process::Command;

pub fn run_doctor() -> Result<()> {
    let mut has_error = false;
    let mut error_msg = String::new();

    // Check Docker
    if let Err(e) = check_dependency(Dependency::Docker) {
        has_error = true;
        error_msg.push_str(&format!("{}\n", e));
    }

    // Check Nix
    if let Err(e) = check_dependency(Dependency::Nix) {
        has_error = true;
        error_msg.push_str(&format!("{}\n", e));
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
