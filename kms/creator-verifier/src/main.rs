use alloy_primitives::{Address, Signature};
use anyhow::{Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Verify creator signatures and recover public keys"
)]
struct Args {
    /// Hex-encoded message with 65-byte signature appended
    #[arg(help = "Hex string containing message followed by 65-byte signature")]
    hex_string: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let hex_string = &args.hex_string;

    // Decode hex string
    let bytes = hex::decode(hex_string).context("Failed to decode hex string")?;

    if bytes.len() <= 65 {
        anyhow::bail!("Input too short - must contain message plus 65 byte signature");
    }

    // Split into message and signature
    let msg_bytes = &bytes[..bytes.len() - 65];

    println!("Recovered msg: {}", hex::encode(msg_bytes));
    println!("Base64 msg: {}", BASE64_STANDARD.encode(msg_bytes));

    let sig_bytes = &bytes[bytes.len() - 65..];

    // Parse signature
    let signature = Signature::from_bytes_and_parity(&sig_bytes[..64], (sig_bytes[64] - 27) == 1)
        .context("Failed to parse signature")?;

    // Recover signer address
    let signer = signature
        .recover_from_msg(msg_bytes)
        .context("Failed to recover signer")?;

    println!(
        "Recovered pubkey: {}",
        hex::encode(signer.to_encoded_point(false).to_bytes())
    );
    println!(
        "Recovered address: {}",
        Address::from_public_key(&signer).to_string()
    );

    Ok(())
}
