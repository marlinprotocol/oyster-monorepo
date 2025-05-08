use crate::args::wallet::WalletArgs;
use alloy::sol;
use clap::{Args, Subcommand};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Relay,
    "src/abis/Relay.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

#[derive(Args)]
pub struct JobArgs {
    #[command(subcommand)]
    pub command: JobCommands,
}

#[derive(Subcommand)]
pub enum JobCommands {
    /// Create a new job
    Create(CreateJobArgs),
    /// Fetch response for a job
    FetchResponse(FetchResponseArgs),
    /// Cancel a job
    Cancel(CancelArgs),
}

#[derive(Args)]
pub struct CreateJobArgs {
    #[command(flatten)]
    pub wallet: WalletArgs,

    /// Execution environment (defaults to 1)
    #[arg(long, default_value = "1")]
    pub env: u8,

    /// Code hash from deployed JS code (transaction hash)
    #[arg(long, required = true)]
    pub code_hash: String,

    /// Code inputs for the worker
    #[arg(long)]
    pub input_file: Option<String>,

    /// Maximum time allowed for executors to complete computation
    #[arg(long, required = true)]
    pub user_timeout: u64,

    /// Max gas price multiplier (e.g: 1.5, 2, 2.5)
    #[arg(long, default_value = "1.5")]
    pub max_gas_price: f64,

    /// Callback contract address
    #[arg(long, required = true)]
    pub callback_contract_address: String,

    /// Gas limit for callback function
    #[arg(long, required = true)]
    pub callback_gas_limit: u64,

    /// Address to receive compensation if job fails (defaults to sender's address)
    #[arg(long)]
    pub refund_account: Option<String>,
}

#[derive(Args)]
pub struct FetchResponseArgs {
    /// Job ID to fetch the response for
    #[arg(short, long, required = true)]
    pub job_transaction_hash: String,
}

#[derive(Args)]
pub struct CancelArgs {
    #[command(flatten)]
    pub wallet: WalletArgs,

    /// Job ID to cancel (transaction hash of job creation)
    #[arg(short, long, required = true)]
    pub job_transaction_hash: String,
}
