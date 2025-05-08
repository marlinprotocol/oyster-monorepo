use std::fs::read;

use anyhow::{Context, Result, bail};
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use clap::Parser;

/// Extend PCRs
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PCR index, should be within [16, 31] inclusive
    #[arg(short, long)]
    index: u8,

    /// path to file whose contents to extend the PCR with
    #[arg(short, long)]
    contents_path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let data = read(args.contents_path).context("failed to read file contents")?;
    let req = Request::ExtendPCR {
        index: args.index.into(),
        data,
    };

    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        bail!("failed to initialize nsm");
    }

    let resp = nsm_process_request(nsm_fd, req);
    nsm_exit(nsm_fd);
    if let Response::Error(e) = resp {
        bail!("failed to extend pcr: {e:?}");
    };

    Ok(())
}
