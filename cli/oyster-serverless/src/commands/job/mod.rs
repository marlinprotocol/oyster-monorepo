mod cancel;
mod create;
mod fetch;
mod types;

pub use types::{JobArgs, JobCommands};

use anyhow::Result;

/// Run the job command based on args
pub async fn run_job(args: JobArgs) -> Result<()> {
    match args.command {
        JobCommands::Create(create_args) => create::create_job(create_args).await,
        JobCommands::FetchResponse(fetch_args) => fetch::fetch_response(fetch_args).await,
        JobCommands::Cancel(cancel_args) => cancel::cancel_job(cancel_args).await,
    }
}
