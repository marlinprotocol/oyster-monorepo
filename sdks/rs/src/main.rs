use clap::Parser;
use oyster::attestation::{get, verify, AttestationExpectations};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// endpoint of the attestation server (http://<ip:port>)
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// maximum age of attestation (in milliseconds)
    #[arg(short, long, default_value = "60000")]
    max_age: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let attestation_doc = get(cli.endpoint.parse()?).await?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as usize;
    let decoded = verify(
        &attestation_doc,
        AttestationExpectations {
            age: Some((cli.max_age, now)),
            ..Default::default()
        },
    )?;
    println!("verification successful: {:?}", decoded);
    println!("pcr0: {}", hex::encode(decoded.pcrs[0]));
    println!("pcr1: {}", hex::encode(decoded.pcrs[1]));
    println!("pcr2: {}", hex::encode(decoded.pcrs[2]));
    println!("root pubkey: {}", hex::encode(decoded.root_public_key));
    println!("enclave pubkey: {}", hex::encode(decoded.public_key));

    Ok(())
}
