mod governance_contract;

use std::collections::HashMap;
use std::fs::{read, read_to_string};
use std::sync::Arc;


use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256, U256};
use ethers::utils::keccak256;
use governance_contract::{fetch_chain_contexts, tally_votes, GovernanceConfig, GovernanceContract, VoteOutcome};
use libsodium_sys::crypto_scalarmult_base;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use ureq;
use warp::Filter;
use k256::sha2::{Digest, Sha384};

use crate::governance_contract::fetch_total_supply;

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

#[derive(Debug)]
pub struct AppConfig {
    pub rpc_url: String,
    pub default_api_key: String,
    pub api_keys: Vec<String>,
    pub chain_ids: Vec<u64>,
    pub rpc_index: Vec<usize>,
    pub gov_contract: String,
    pub proposal_id: String,
    pub data_hash: String,
    pub start_ts: u64,
}




#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("[main] Starting enclave service initialization...");

    let args = Args::parse();

    // TODO : Whenever the application fails at any step, still run the api server to allow knowing where it failed 
    // Step 1: Load config from init-params
    let app_config = match load_app_config() {
        Ok(cfg) => {
            println!("[main] Loaded enclave config: {:?}", cfg);
            cfg
        }
        Err(e) => {
            eprintln!("[main] Failed to load enclave config: {:?}", e);
            return Ok(()); // or return Err(e) if you want to stop
        }
    };

    let init_params_str = match read_to_string(&args.init_params_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[main] Failed to read init params: {:?}", e);
            return Ok(());
        }
    };

    let init_params = match serde_json::from_str::<InitParamsList>(&init_params_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[main] Failed to parse init params: {:?}", e);
            return Ok(());
        }
    };

    let pcr16_sha256_bytes = match BASE64_STANDARD.decode(init_params.digest) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[main] Failed to decode digest: {:?}", e);
            return Ok(());
        }
    };

    let pcr16_sha256 = H256::from_slice(&pcr16_sha256_bytes);
    println!("[main] Loaded PCR16 SHA256: {}", hex::encode(pcr16_sha256.as_bytes()));

    // let pcr16_sha384 = match read("/app/init-params-digest") {
    //     Ok(contents) => {
    //         let bytes = Bytes::from(contents);
    //         println!("[main] Loaded PCR16 SHA384: {}", hex::encode(bytes.as_ref()));
    //         bytes
    //     }
    //     Err(e) => {
    //         eprintln!("[main] Failed to read /app/init-params-digest: {:?}", e);
    //         Bytes::new() // empty fallback
    //     }
    // };

    let mut pcr_hasher = Sha384::new();
    pcr_hasher.update([0u8; 48]);
    pcr_hasher.update(pcr16_sha256_bytes);
    let pcr16_sha384: [u8; 48] = pcr_hasher.finalize().into();

    println!("[main] Loaded PCR16 SHA384: {}", hex::encode(pcr16_sha384));

    // Step 2: Construct GovernanceConfig
    let gov_config = GovernanceConfig {
        rpc_url: app_config.rpc_url.clone(),
        api_key: app_config.default_api_key.clone(),
        gov_contract: match app_config.gov_contract.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("[main] Failed to parse gov_contract: {:?}", e);
                return Ok(());
            }
        },
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

    let supply = fetch_total_supply(&chain_contexts[0]).await
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch total supply for chain {}", chain_contexts[0].chain_id))?;

    println!("Total supply for chain {}: {}", chain_contexts[0].chain_id, supply);

    let privkey =
        fetch_signing_key(&args.derive_endpoint).context("failed to fetch signing key")?;

    let vote_result_bytes = serialize_vote_result(&tally, supply);

    // let data_hash_h256 = H256::from_slice(
    //     &hex::decode(app_config.data_hash.trim_start_matches("0x"))
    //         .context("failed to decode data_hash hex")?,
    // );

    // TODO: Implement logic to calculate `data_hash_h256` based on votes and network data.
    // Then match it with the `data_hash` from init params.
    // This requires aggregating vote results and network-specific parameters to derive the hash.

    let pcr16_sha384_bytes = Bytes::from(pcr16_sha384.to_vec());
    let hash = compute_vote_result_hash(pcr16_sha256, &pcr16_sha384_bytes, &vote_result_bytes);

    let enclave_sig = sign_vote_result(hash, privkey)?;

    let result = VoteResult {
        enclave_sig,
        pcr16_sha256,
        pcr16_sha384: pcr16_sha384_bytes,
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

// TODO : Create a single function to fetch both encryption and signing keys
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

fn serialize_vote_result(results: &HashMap<VoteOutcome, U256>, supply: U256) -> Bytes {
    let mut encoded = vec![];

    for variant in [
        VoteOutcome::Passed,
        VoteOutcome::Failed,
        VoteOutcome::Pending,
        VoteOutcome::Vetoed,
    ] {
        let vote_count = results.get(&variant).cloned().unwrap_or_default();
        let mut buf = [0u8; 32];
        vote_count.to_big_endian(&mut buf);
        encoded.extend_from_slice(&buf);
    }

    // Add supply as the final 32 bytes
    let mut supply_buf = [0u8; 32];
    supply.to_big_endian(&mut supply_buf);
    encoded.extend_from_slice(&supply_buf);

    Bytes::from(encoded)
}

fn compute_vote_result_hash(
    pcr16_sha256: H256,
    pcr16_sha384: &Bytes,
    vote_result_bytes: &Bytes,
) -> H256 {
    let mut combined = vec![];
    combined.extend_from_slice(pcr16_sha256.as_bytes());
    combined.extend_from_slice(pcr16_sha384.as_ref());
    combined.extend_from_slice(vote_result_bytes.as_ref());

    H256::from(keccak256(combined))
}

fn sign_vote_result(hash: H256, privkey_array: [u8; 32]) -> Result<H256> {
    let secp = Secp256k1::signing_only();

    let secret_key = SecretKey::from_byte_array(privkey_array)
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

pub fn load_app_config() -> Result<AppConfig> {
    use std::fs;
    // TODO : move this to init_params args only, hard coded for now
    Ok(AppConfig {
        rpc_url: fs::read_to_string("/init-params/config/rpc_url")?.trim().to_string(),
        default_api_key: fs::read_to_string("/init-params/secrets/default_api_key")?.trim().to_string(),
        api_keys: serde_json::from_str(&fs::read_to_string("/init-params/secrets/api_keys.json")?)?,
        chain_ids: serde_json::from_str(&fs::read_to_string("/init-params/config/chain_ids.json")?)?,
        rpc_index: serde_json::from_str(&fs::read_to_string("/init-params/config/rpc_index.json")?)?,
        gov_contract: fs::read_to_string("/init-params/config/gov_contract")?.trim().to_string(),
        proposal_id: fs::read_to_string("/init-params/params/proposal_id")?.trim().to_string(),
        data_hash: fs::read_to_string("/init-params/params/data_hash")?.trim().to_string(),
        start_ts: fs::read_to_string("/init-params/params/start_ts")?
            .trim()
            .parse()
            .context("Invalid start_ts format (expected u64)")?,
    })
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
