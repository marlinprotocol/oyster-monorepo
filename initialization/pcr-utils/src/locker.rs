use anyhow::{Result, bail};
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use clap::Parser;

/// Lock PCRs
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PCR index, should be within [16, 31] inclusive
    #[arg(short, long)]
    index: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let req = Request::LockPCR {
        index: args.index.into(),
    };

    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        bail!("failed to initialize nsm");
    }

    let resp = nsm_process_request(nsm_fd, req);
    nsm_exit(nsm_fd);
    if let Response::Error(e) = resp {
        bail!("failed to lock pcr: {e:?}");
    };

    Ok(())
}
