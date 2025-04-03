use std::fs;
use std::net::SocketAddr;

use alloy::hex::ToHexExt;
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::ws::WsConnect;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use tracing::Instrument;
use tracing::{error, info, info_span};
use tracing_subscriber::EnvFilter;

use cp::aws;
use cp::market;
use cp::server;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
/// Control plane for Oyster
struct Cli {
    /// AWS profile
    #[clap(long, value_parser)]
    profile: String,

    /// AWS keypair name
    #[clap(long, value_parser)]
    key_name: String,

    /// AWS regions
    #[clap(
        long,
        value_parser,
        default_value = "us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,sa-east-1,eu-north-1,eu-west-3,eu-west-2,eu-west-1,eu-central-1,eu-central-2,eu-south-1,eu-south-2,me-south-1,me-central-1,af-south-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-east-1"
    )]
    regions: String,

    /// RPC url
    #[clap(long, value_parser)]
    rpc: String,

    /// Rates location
    #[clap(long, value_parser)]
    rates: String,

    /// Bandwidth Rates location
    #[clap(long, value_parser)]
    bandwidth: String,

    /// Contract address
    #[clap(long, value_parser)]
    contract: String,

    /// Provider address
    #[clap(long, value_parser)]
    provider: String,

    /// Blacklist location
    #[clap(long, value_parser, default_value = "")]
    blacklist: String,

    /// Whitelist location
    #[clap(long, value_parser, default_value = "")]
    whitelist: String,

    /// Address Blacklist location
    #[clap(long, value_parser, default_value = "")]
    address_blacklist: String,

    /// Address Whitelist location
    #[clap(long, value_parser, default_value = "")]
    address_whitelist: String,

    /// Metadata server port
    #[clap(long, value_parser, default_value = "8080")]
    port: u16,
}

async fn parse_file(filepath: String) -> Result<Vec<String>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();

    Ok(lines)
}

async fn parse_compute_rates_file(filepath: String) -> Result<Vec<market::RegionalRates>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let rates: Vec<market::RegionalRates> =
        serde_json::from_str(&contents).context("failed to parse rates file")?;

    Ok(rates)
}

async fn parse_bandwidth_rates_file(filepath: String) -> Result<Vec<market::GBRateCard>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let rates: Vec<market::GBRateCard> =
        serde_json::from_str(&contents).context("failed to parse rates file")?;

    Ok(rates)
}

async fn get_chain_id_from_rpc_url(url: String) -> Result<String> {
    let provider = ProviderBuilder::new()
        .on_ws(WsConnect::new(url))
        .await
        .context("failed to create websocket provider")?;
    let chain_id = provider
        .get_chain_id()
        .await
        .context("failed to fetch chain id")?;

    Ok(chain_id.to_string())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    info!(?cli.profile);
    info!(?cli.key_name);
    info!(?cli.rpc);
    info!(?cli.rates);
    info!(?cli.bandwidth);
    info!(?cli.contract);
    info!(?cli.provider);
    info!(?cli.blacklist);
    info!(?cli.whitelist);
    info!(?cli.address_blacklist);
    info!(?cli.address_whitelist);
    info!(?cli.port);

    let regions: Vec<String> = cli.regions.split(',').map(|r| (r.into())).collect();

    let eif_whitelist = if !cli.whitelist.is_empty() {
        let eif_whitelist_vec: Vec<String> = parse_file(cli.whitelist)
            .await
            .context("Failed to parse eif whitelist")?;
        // leak memory to get static references
        // will be cleaned up once program exits
        // alternative to OnceCell equivalents
        let eif_whitelist = &*Box::leak(eif_whitelist_vec.into_boxed_slice());

        Some(eif_whitelist)
    } else {
        None
    };
    let eif_blacklist = if !cli.blacklist.is_empty() {
        let eif_blacklist_vec: Vec<String> = parse_file(cli.blacklist)
            .await
            .context("Failed to parse eif blacklist")?;
        // leak memory to get static references
        // will be cleaned up once program exits
        // alternative to OnceCell equivalents
        let eif_blacklist = &*Box::leak(eif_blacklist_vec.into_boxed_slice());

        Some(eif_blacklist)
    } else {
        None
    };

    let aws = aws::Aws::new(
        cli.profile,
        &regions,
        cli.key_name,
        eif_whitelist,
        eif_blacklist,
    )
    .await;

    aws.generate_key_pair()
        .await
        .context("Failed to generate key pair")?;

    for region in regions.clone() {
        aws.key_setup(region.clone())
            .await
            .with_context(|| format!("Failed to setup key pair in {region}"))?;
    }

    let compute_rates = parse_compute_rates_file(cli.rates)
        .await
        .context("failed to parse computes rates file")?;
    let bandwidth_rates = parse_bandwidth_rates_file(cli.bandwidth)
        .await
        .context("failed to parse bandwidth rates file")?;

    let address_whitelist_vec: Vec<String> = parse_file(cli.address_whitelist)
        .await
        .context("Failed to parse address whitelist")?;
    let address_blacklist_vec: Vec<String> = parse_file(cli.address_blacklist)
        .await
        .context("Failed to parse address blacklist")?;

    // leak memory to get static references
    // will be cleaned up once program exits
    // alternative to OnceCell equivalents
    let compute_rates: &'static [market::RegionalRates] =
        Box::leak(compute_rates.into_boxed_slice());
    let bandwidth_rates: &'static [market::GBRateCard] =
        Box::leak(bandwidth_rates.into_boxed_slice());
    let address_whitelist: &'static [String] = Box::leak(address_whitelist_vec.into_boxed_slice());
    let address_blacklist: &'static [String] = Box::leak(address_blacklist_vec.into_boxed_slice());
    let regions: &'static [String] = Box::leak(regions.into_boxed_slice());
    let chain = get_chain_id_from_rpc_url(cli.rpc.clone())
        .await
        .context("Failed to fetch chain_id")?;

    // Initialize job registry for terminated jobs
    let job_registry = market::JobRegistry::new("terminated_jobs.txt".to_string()).await?;

    // Start periodic job registry persistence task
    let registry_clone = job_registry.clone();
    tokio::spawn(async move {
        registry_clone.run_periodic_save(10).await; // Save every 10 seconds
    });

    let job_id = market::JobId {
        id: B256::ZERO.encode_hex_with_prefix(),
        operator: cli.provider.clone(),
        contract: cli.contract.clone(),
        chain,
    };

    tokio::spawn(
        server::serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], cli.port)),
            job_id.clone(),
        )
        .instrument(info_span!("server")),
    );

    let ethers = market::EthersProvider {
        contract: cli
            .contract
            .parse::<Address>()
            .context("failed to parse contract address")?,
        provider: cli
            .provider
            .parse::<Address>()
            .context("failed to parse provider address")?,
    };

    market::run(
        aws,
        ethers,
        cli.rpc,
        regions,
        compute_rates,
        bandwidth_rates,
        address_whitelist,
        address_blacklist,
        job_id,
        job_registry,
    )
    .instrument(info_span!("main"))
    .await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // seems messy, see if there is a better way
    let mut filter = EnvFilter::new("info,aws_config=warn");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().await.inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
