use clap::Parser;
use ethers::types::Bytes;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct VoteResult {
    pub enclave_sig: Bytes,
    pub result_data: Bytes,
}

#[derive(Debug, Serialize, Clone)]
pub struct ApiResponse {
    pub enclave_sig: Bytes,
    pub result_data: Bytes,
    pub in_progress: bool,
    pub error: Option<String>,
}

#[derive(Parser)]
pub struct Args {
    /// Init params file
    #[arg(long, default_value = "/app/init-params")]
    pub init_params_path: String,

    /// Derive server endpoint
    #[arg(long, default_value = "http://127.0.0.1:1100")]
    pub derive_endpoint: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum VoteOutcome {
    Yes = 0,
    No = 1,
    Abstain = 2,
    NoWithVeto = 3,
}

impl TryFrom<u8> for VoteOutcome {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> anyhow::Result<Self> {
        match value {
            0 => Ok(VoteOutcome::Yes),
            1 => Ok(VoteOutcome::No),
            2 => Ok(VoteOutcome::Abstain),
            3 => Ok(VoteOutcome::NoWithVeto),
            _ => Err(anyhow::anyhow!("Invalid vote outcome byte: {}", value)),
        }
    }
}
