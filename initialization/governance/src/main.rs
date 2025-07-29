mod governance_contract;

use std::collections::HashMap;
use std::fs::{read, read_to_string};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use ethers::abi::{Address, Token, encode};
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256, U256};

use governance_contract::{
    GovernanceConfig, GovernanceContract, VoteOutcome, fetch_chain_contexts, tally_votes,
};
use k256::sha2::{Digest, Sha256};
use libsodium_sys::{crypto_scalarmult_base, sodium_init};
use secp256k1::{Message, Secp256k1, SecretKey};

use serde::{Deserialize, Serialize};
use ureq;
use warp::Filter;

use crate::governance_contract::fetch_total_supply;

#[derive(Debug, Serialize)]
pub struct VoteResult {
    pub enclave_sig: Bytes,
    pub result_data: Bytes,
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
    let (chain_contexts, network_hash) = fetch_chain_contexts(gov_config, &contract).await?;
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

    // SAFETY: no params, return value is checked properly
    if unsafe { sodium_init() } < 0 {
        bail!("failed to init libsodium");
    }

    unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()) };

    // SAFETY: pk and sk are the right size
    // cannot fail, ignore return value

    let proposal_id_bytes: [u8; 32] = hex::decode(app_config.proposal_id.trim_start_matches("0x"))
        .context("failed to decode proposal_id hex")?
        .try_into()
        .map_err(|_| anyhow!("proposal_id is not 32 bytes"))?;

    let (tally, vote_hash) = tally_votes(
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

    let supply = fetch_total_supply(&chain_contexts[0])
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to fetch total supply for chain {}",
                chain_contexts[0].chain_id
            )
        })?;

    println!(
        "Total supply for chain {}: {}",
        chain_contexts[0].chain_id, supply
    );

    let privkey =
        fetch_signing_key(&args.derive_endpoint).context("failed to fetch signing key")?;

    println!(
        "[main] network_hash :{}, vote_hash :{}",
        hex::encode(network_hash),
        hex::encode(vote_hash)
    );

    let gov_contract_addr: ethers::types::Address = app_config
        .gov_contract
        .parse()
        .context("Invalid contract address")?;

    let data_hash = compute_result_hash(
        gov_contract_addr,
        U256::from(app_config.start_ts),
        network_hash.into(),
        vote_hash.into(),
    );
    println!("Result hash (sha256): 0x{}", hex::encode(data_hash));
    
    let vote_result_tokens = serialize_vote_result(&tally, supply);

    // Hash uses the *flattened* tokens
    let hash = compute_vote_result_hash(
        data_hash.into(),
        proposal_id_bytes,
        vote_result_tokens.clone(),
    );

    let enclave_sig = sign_vote_result(hash, privkey)?;

    let mut tokens = vec![Token::FixedBytes(proposal_id_bytes.to_vec())];
    tokens.extend(vote_result_tokens);

    let result_data = encode(&tokens);

    let result = VoteResult {
        enclave_sig: enclave_sig.into(),
        result_data : result_data.into(),
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

fn compute_result_hash(
    gov_contract_addr: ethers::types::Address,
    start_ts: U256,
    network_hash: H256,
    vote_hash: H256,
) -> H256 {
    // ABI-encode the parameters
    let encoded = ethers::abi::encode(&[
        Token::Address(gov_contract_addr),
        Token::Uint(start_ts),
        Token::FixedBytes(network_hash.as_bytes().to_vec()),
        Token::FixedBytes(vote_hash.as_bytes().to_vec()),
    ]);

    // Compute SHA-256 over the ABI-encoded buffer
    let result = Sha256::digest(&encoded);
    H256::from_slice(&result)
}

// Serializes the `VoteDecisionResult` (struct of 5 uint256s)
fn serialize_vote_result(results: &HashMap<VoteOutcome, U256>, supply: U256) -> Vec<Token> {
    let yes = results.get(&VoteOutcome::Passed).cloned().unwrap_or_default();
    let no = results.get(&VoteOutcome::Failed).cloned().unwrap_or_default();
    let abstain = results.get(&VoteOutcome::Pending).cloned().unwrap_or_default();
    let no_with_veto = results.get(&VoteOutcome::Vetoed).cloned().unwrap_or_default();

    vec![
        Token::Uint(yes),
        Token::Uint(no),
        Token::Uint(abstain),
        Token::Uint(no_with_veto),
        Token::Uint(supply),
    ]
}

// Fully equivalent to Solidity's abi.encode(contractDataHash, proposalId, voteDecisionResult)
fn compute_vote_result_hash(
    contract_data_hash: [u8; 32], // bytes32
    proposal_id: [u8; 32],        // bytes32
    vote_result: Vec<Token>,      // 5 x uint256 tokens
) -> H256 {
    let mut all_tokens = vec![
        Token::FixedBytes(contract_data_hash.to_vec()), // bytes32
        Token::FixedBytes(proposal_id.to_vec()),        // bytes32
    ];

    all_tokens.extend(vote_result); // Append 5 uint256s

    let encoded = encode(&all_tokens);

    let digest = Sha256::digest(&encoded);
    H256::from_slice(&digest)
}

fn sign_vote_result(hash: H256, privkey_array: [u8; 32]) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();

    let secret_key = SecretKey::from_byte_array(privkey_array)
        .map_err(|e| anyhow!("failed to create SecretKey: {}", e))?;

    let msg = Message::from_digest(hash.into());

    let sig = secp.sign_ecdsa_recoverable(msg, &secret_key);
    let (recovery_id, compact_sig) = sig.serialize_compact();

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&compact_sig[..]);
    sig_bytes[64] = (Into::<i32>::into(recovery_id) as u8) + 27;

    Ok(sig_bytes.to_vec())
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
        rpc_url: fs::read_to_string("/init-params/config/rpc_url")?
            .trim()
            .to_string(),
        default_api_key: fs::read_to_string("/init-params/secrets/default_api_key")?
            .trim()
            .to_string(),
        api_keys: serde_json::from_str(&fs::read_to_string("/init-params/secrets/api_keys.json")?)?,
        chain_ids: serde_json::from_str(&fs::read_to_string(
            "/init-params/config/chain_ids.json",
        )?)?,
        rpc_index: serde_json::from_str(&fs::read_to_string(
            "/init-params/config/rpc_index.json",
        )?)?,
        gov_contract: fs::read_to_string("/init-params/config/gov_contract")?
            .trim()
            .to_string(),
        proposal_id: fs::read_to_string("/init-params/params/proposal_id")?
            .trim()
            .to_string(),
        data_hash: fs::read_to_string("/init-params/params/data_hash")?
            .trim()
            .to_string(),
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
