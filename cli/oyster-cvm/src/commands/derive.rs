use std::collections::HashMap;

use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{bail, Context, Result};
use clap::Args;
use lazy_static::lazy_static;
use tracing::info;

/// Get KMS derived public keys or addresses
///
/// For image based KMS:
///   --image-id <IMAGE_ID>
///
/// For contract based KMS:
///   --contract-address <ADDRESS> --chain-id <ID>
#[derive(Args, Debug)]
pub struct KmsDeriveArgs {
    /// KMS endpoint for fetching public key for encryption
    #[arg(short = 'k', long)]
    pub kms_endpoint: Option<String>,

    /// KMS response signature verification key
    #[arg(long)]
    pub kms_verification_key: Option<String>,

    /// Image ID of deployed enclave
    #[arg(short = 'i', long, conflicts_with_all = ["contract_address", "chain_id"])]
    pub image_id: Option<String>,

    /// Key derivation path
    #[arg(short = 'p', long)]
    pub path: String,

    /// KMS verify contract address
    #[arg(long, requires = "chain_id")]
    pub contract_address: Option<String>,

    /// Chain ID
    #[arg(long, requires = "contract_address")]
    pub chain_id: Option<u64>,

    /// Key Derivation Type
    #[arg(long, value_parser = ["secp256k1/public", "secp256k1/address/ethereum", "ed25519/public", "ed25519/address/solana", "x25519/public"])]
    pub key_type: String,
}

struct KmsRootServer {
    endpoint: String,
    pubkey: String,
}

pub async fn kms_derive(args: KmsDeriveArgs) -> Result<()> {
    let uri = if let Some(image_id) = args.image_id {
        format!(
            "/derive/{}?image_id={}&path={}",
            args.key_type, image_id, args.path
        )
    } else {
        format!(
            "/derive/{}?address={}&path={}",
            args.key_type,
            args.contract_address.unwrap(),
            args.path
        )
    };
    let kms_endpoint: String = if let Some(kms_endpoint) = args.kms_endpoint {
        kms_endpoint
    } else if let Some(chain_id) = args.chain_id {
        KMS_ROOT_SERVERS
            .get(&chain_id)
            .context(format!("No KMS endpoint found for chain ID {}", chain_id))?
            .endpoint
            .clone()
    } else {
        "http://image-v4.kms.box:1101".into()
    };

    let mut response = ureq::get(kms_endpoint + &uri)
        .call()
        .context("failed to call KMS root server")?;

    if response.status() != 200 {
        bail!("failed to get encryption key from kms root server");
    }
    // get the header from response
    let signature_bytes = hex::decode(
        response
            .headers()
            .get("x-marlin-kms-signature")
            .context("failed to get signature for encryption key from kms root server")?,
    )
    .context("failed to decode signature")?;

    let body_bytes = response
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?;

    let mut hasher = Sha256::new();
    hasher.update(uri);
    hasher.update(&body_bytes);
    let digest: [u8; 32] = hasher.finalize().into();

    let signature = k256::ecdsa::Signature::from_slice(&signature_bytes[0..64])
        .context("failed to parse signature for encryption key from kms root server")?;
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(signature_bytes[64] - 27)
        .context("failed to parse recovery id from kms root server signature")?;
    let verifying_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
            .context("failed to recover pubkey from kms root server signature")?;
    let pubkey = hex::encode(&verifying_key.to_encoded_point(false).as_bytes()[1..]);

    let kms_verification_key = if let Some(kms_verification_key) = args.kms_verification_key {
        kms_verification_key
    } else if let Some(chain_id) = args.chain_id {
        KMS_ROOT_SERVERS
            .get(&chain_id)
            .context(format!("No KMS endpoint found for chain ID {}", chain_id))?
            .pubkey
            .clone()
    } else {
        "14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276".to_string()
    };

    if pubkey != kms_verification_key.to_lowercase() {
        bail!("signature verifaction failed: unexpected signer");
    }
    if args.key_type.contains("address") {
        info!(
            address =
                String::from_utf8(body_bytes).context("Invalid UTF-8 bytes in KMS response")?,
            "kms derived address"
        );
    } else {
        info!(key = hex::encode(&body_bytes), "kms derived key");
    }

    Ok(())
}

lazy_static! {
    static ref KMS_ROOT_SERVERS: HashMap<u64, KmsRootServer> = {
        let mut root_servers = HashMap::new();
        root_servers.insert(
            42161,
            KmsRootServer {
                endpoint: "http://arbone-v4.kms.box:1101".to_string(),
                pubkey: "4ade7c22061165358c46fce1c7e9d4c2c6c12ffbe7e61d76ea98a68659c09a777da06b15df2cd621c5988534fb0716230e9eaa6ae562f625bba3e63ebb2ebc4f".to_string()
            }
        );
        root_servers
    };
}
