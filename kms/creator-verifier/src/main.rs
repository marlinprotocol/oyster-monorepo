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
    message_hex: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Decode hex string
    let bytes = hex::decode(&args.message_hex).context("Failed to decode hex string")?;

    if bytes.len() <= 64 + 32 + 65 {
        anyhow::bail!("Input too short - must contain seed, secp256k1 pubkey, x25519 pubkey plus 65 byte signature");
    }

    // Split into message and signature
    let msg_bytes = &bytes[..bytes.len() - 65];

    println!("Recovered msg: {}", hex::encode(msg_bytes));

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

    println!(
        "Base64 seed: {}",
        BASE64_STANDARD.encode(&msg_bytes[0..bytes.len() - 161])
    );
    println!(
        "Secp256k1 pubkey: {}",
        hex::encode(&msg_bytes[bytes.len() - 161..bytes.len() - 97])
    );
    println!(
        "Secp256k1 address: {}",
        Address::from_raw_public_key(&msg_bytes[bytes.len() - 161..bytes.len() - 97])
    );
    println!(
        "X25519 pubkey: {}",
        hex::encode(&msg_bytes[bytes.len() - 97..bytes.len() - 65])
    );

    Ok(())
}
