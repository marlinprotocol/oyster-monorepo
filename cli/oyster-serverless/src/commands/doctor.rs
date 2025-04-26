use crate::types::Dependency;
use anyhow::Result;
use clap::Args;
use std::process::Command;
use tracing::{error, info};

#[derive(Args)]
pub struct DoctorArgs {
    /// Perform Docker checks
    #[arg(short, long)]
    docker: bool,
}

pub fn run_doctor(args: DoctorArgs) -> Result<()> {
    let all = !args.docker;

    let docker = args.docker || all;

    let mut has_error = false;
    let mut error_msg = String::new();

    if docker {
        // Check Docker
        if let Err(e) = check_dependency(Dependency::Docker) {
            has_error = true;
            error_msg.push_str(&format!("{}\n", e));
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
