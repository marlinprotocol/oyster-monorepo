mod config;
mod governance_contract;

use std::collections::HashMap;
use std::fs::{read, read_to_string};
use std::sync::Arc;

use crate::config::load_app_config;
use crate::governance_contract::{
    GovernanceConfig, GovernanceContract, VoteOutcome, fetch_chain_contexts, tally_votes,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256, U256};
use ethers::utils::keccak256;
use libsodium_sys::crypto_scalarmult_base;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use ureq;
use warp::Filter;

#[derive(Debug, Serialize)]
pub struct VoteResult {
    pub enclave_sig: H256,
    pub pcr16_sha256: H256,
    pub pcr16_sha384: Bytes,
    pub vote_result: Bytes,
}

#[derive(Parser)]
struct Args {
    /// Init params file
    #[arg(long, default_value = "/app/init-params")]
    init_params_path: String,

    /// Derive server endpoint
    #[arg(long, default_value = "http://127.0.0.1:1100")]
    derive_endpoint: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("[main] Starting enclave service initialization...");

    let args = Args::parse();

    // Step 1: Load config from init-params
    let app_config = load_app_config()?;
    println!("[main] Loaded enclave config ✅");

    let init_params_str = read_to_string(args.init_params_path)
        .context("failed to read init params, should never happen")?;

    let init_params = serde_json::from_str::<InitParamsList>(&init_params_str)
        .context("failed to parse init params")?;

    let pcr16_sha256_bytes = BASE64_STANDARD
        .decode(init_params.digest)
        .context("failed to decode digest")?;
    let pcr16_sha256 = H256::from_slice(&pcr16_sha256_bytes);

    let pcr16_sha384 =
        Bytes::from(read("/app/init-params-digest").context("failed to read file contents")?);

    // Step 2: Construct GovernanceConfig
    let gov_config = GovernanceConfig {
        rpc_url: app_config.rpc_url.clone(),
        api_key: app_config.default_api_key.clone(),
        gov_contract: app_config.gov_contract.parse()?,
        api_keys: app_config.api_keys,
        chain_ids: app_config.chain_ids,
        rpc_indexes: app_config.rpc_index,
    };

    let provider = Provider::<Http>::try_from(format!(
        "{}/{}",
        gov_config.rpc_url.trim_end_matches('/'),
        gov_config.api_key
    ))
    .context("Invalid RPC URL or failed to connect")?;
    let provider = Arc::new(provider);

    let contract = GovernanceContract::new(gov_config.gov_contract, provider.clone());
    // Step 3: Fetch chain contexts from governance contract
    let chain_contexts = fetch_chain_contexts(gov_config, &contract).await?;
    println!("[main] Loaded chain contexts from contract:");

    for ctx in &chain_contexts {
        println!(
            "  • chain_id: {} | rpc_urls: {} | token: {}",
            ctx.chain_id,
            ctx.rpc_urls.join(", "),
            ctx.token_address
        );
    }

    let sk =
        fetch_encryption_key(&args.derive_endpoint).context("failed to fetch encryption key")?;
    let mut pk = [0u8; 32];
    unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()) };

    // SAFETY: pk and sk are the right size
    // cannot fail, ignore return value

    let proposal_id_bytes: [u8; 32] = hex::decode(app_config.proposal_id.trim_start_matches("0x"))
        .context("failed to decode proposal_id hex")?
        .try_into()
        .map_err(|_| anyhow!("proposal_id is not 32 bytes"))?;
    let tally = tally_votes(
        proposal_id_bytes,
        &contract,
        &chain_contexts,
        &pk,
        &sk,
        app_config.start_ts,
    )
    .await?;

    for (outcome, total_power) in tally.iter() {
        println!("{:?}: {}", outcome, total_power);
    }

    let privkey =
        fetch_signing_key(&args.derive_endpoint).context("failed to fetch signing key")?;

    let vote_result_bytes = serialize_vote_result(&tally);

    let data_hash_h256 = H256::from_slice(
        &hex::decode(app_config.data_hash.trim_start_matches("0x"))
            .context("failed to decode data_hash hex")?,
    );

    // TODO: Implement logic to calculate `data_hash_h256` based on votes and network data.
    // This requires aggregating vote results and network-specific parameters to derive the hash.

    let hash = compute_vote_result_hash(
        data_hash_h256,
        pcr16_sha256,
        &pcr16_sha384,
        &vote_result_bytes,
    );

    let enclave_sig = sign_vote_result(hash, privkey)?;

    let result = VoteResult {
        enclave_sig,
        pcr16_sha256,
        pcr16_sha384,
        vote_result: vote_result_bytes,
    };

    serve_result_api(result).await;

    Ok(())
}

fn fetch_encryption_key(endpoint: &str) -> Result<[u8; 32]> {
    Ok(ureq::get(&(endpoint.to_owned() + "/derive/x25519"))
        .query("path", "gov_key")
        .call()
        .context("failed to call derive server")?
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?
        .as_slice()
        .try_into()
        .context("failed to parse response")?)
}

fn fetch_signing_key(endpoint: &str) -> Result<[u8; 32]> {
    Ok(ureq::get(&(endpoint.to_owned() + "/derive/secp256k1"))
        .query("path", "gov_key")
        .call()
        .context("failed to call derive server")?
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?
        .as_slice()
        .try_into()
        .context("failed to parse reponse")?)
}

fn serialize_vote_result(results: &HashMap<VoteOutcome, U256>) -> Bytes {
    let mut encoded = vec![];

    for variant in [
        VoteOutcome::Pending,
        VoteOutcome::Passed,
        VoteOutcome::Failed,
        VoteOutcome::Vetoed,
    ] {
        let vote_count = results.get(&variant).cloned().unwrap_or_default();
        let mut buf = [0u8; 32];
        vote_count.to_big_endian(&mut buf);
        encoded.extend_from_slice(&buf);
    }

    Bytes::from(encoded)
}

fn compute_vote_result_hash(
    contract_data_hash: H256,
    pcr16_sha256: H256,
    pcr16_sha384: &Bytes,
    vote_result_bytes: &Bytes,
) -> H256 {
    let mut combined = vec![];
    combined.extend_from_slice(contract_data_hash.as_bytes());
    combined.extend_from_slice(pcr16_sha256.as_bytes());
    combined.extend_from_slice(pcr16_sha384.as_ref());
    combined.extend_from_slice(vote_result_bytes.as_ref());

    H256::from(keccak256(combined))
}

fn sign_vote_result(hash: H256, privkey_array: [u8; 32]) -> Result<H256> {
    let secp = Secp256k1::signing_only();

    let secret_key = SecretKey::from_slice(&privkey_array)
        .map_err(|e| anyhow!("failed to create SecretKey: {}", e))?;

    let msg = Message::from_digest(hash.into());

    let sig = secp.sign_ecdsa(msg, &secret_key);
    let sig_bytes = sig.serialize_compact();

    Ok(H256::from_slice(&sig_bytes[..32])) // Truncate for compatibility
}

pub async fn serve_result_api(result: VoteResult) {
    let result = Arc::new(result);

    let route = warp::path("result").and(warp::get()).map({
        let result = result.clone();
        move || warp::reply::json(&*result)
    });

    warp::serve(route).run(([0, 0, 0, 0], 8080)).await;
}

#[derive(Deserialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    #[serde(default = "_default_true")]
    should_attest: bool,
    #[serde(default)]
    should_decrypt: bool,
}

fn _default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct InitParamsList {
    digest: String, // base64 encoded
    params: Vec<InitParam>,
}
