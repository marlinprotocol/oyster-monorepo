use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ecies::encrypt;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // Private key for gas wallet to be used by Oyster enclave
    #[clap(long, value_parser)]
    gas_private_key: String,

    // enclave public key (used to encrypt the data)
    #[clap(long, value_parser)]
    enclave_public_key: String,

    // Operator's private key to sign the data
    #[clap(long, value_parser)]
    operator_private_key: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let gas_private_key_bytes = hex::decode(cli.gas_private_key)
        .context("Failed to hex decode the secret data hex string")?;

    if gas_private_key_bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid length of the gas private key. Provided length is {}",
            gas_private_key_bytes.len()
        ));
    }

    let enclave_public_key = hex::decode(cli.enclave_public_key)
        .context("Failed to hex decode the enclave public key")?;

    // Encrypt gas private key using the enclave 'secp256k1' public key
    let encrypted_gas_private_key_bytes = match encrypt(&enclave_public_key, &gas_private_key_bytes.as_slice()) {
        Ok(encrypted_bytes) => encrypted_bytes,
        Err(err) => {
            return Err(anyhow!(
                "Failed to encrypt the gas private key using enclave public key: {:?}",
                err
            ));
        }
    };

    let operator_private_key = SigningKey::from_slice(
        hex::decode(cli.operator_private_key)
            .context("Failed to decode the user private key hex")?
            .as_slice(),
    )
    .context("Invalid operator signer key")?;

    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(encrypted_gas_private_key_bytes.clone()),
        DynSolValue::Uint(U256::from(sign_timestamp), 256)
    ]);


    let data_hash = keccak256(token_list.abi_encode());

    // Sign the digest using user private key
    let (rs, v) = operator_private_key
        .sign_prehash_recoverable(&data_hash.to_vec())
        .context("Failed to sign the gas private key message using operator private key")?;
    let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

    println!(
        "Encrypted gas key: {}\nSign Timestamp: {}\nSignature: {}",
        hex::encode(encrypted_gas_private_key_bytes),
        sign_timestamp,
        hex::encode(signature)
    );

    Ok(())
}
