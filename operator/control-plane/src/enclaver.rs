use cp::aws;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
/// Control plane for Oyster
struct Cli {
    /// AWS profile
    #[clap(long, value_parser)]
    profile: String,

    /// SSH key name
    #[clap(long, value_parser)]
    key_name: String,

    /// Instance id
    #[clap(long, value_parser)]
    instance: String,

    /// AWS region
    #[clap(long, value_parser, default_value = "ap-south-1")]
    region: String,

    /// AMI family
    #[clap(long, value_parser, default_value = "salmon")]
    family: String,

    /// Enclave image URL
    #[clap(long, value_parser)]
    url: String,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let cli = Cli::parse();

    let aws = aws::Aws::new(cli.profile, &[cli.region.clone()], cli.key_name, None, None).await;
    aws.run_enclave_impl(
        "0x01020304",
        &cli.family,
        &cli.instance,
        &cli.region,
        &cli.url,
        2,
        4096,
        32,
        false,
        &[],
    )
    .await
    .context("could not deploy enclave")?;

    Ok(())
}
