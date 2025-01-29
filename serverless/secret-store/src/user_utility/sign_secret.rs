use std::collections::HashMap;
use std::fs;

use alloy::consensus::Transaction;
use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use alloy::signers::utils::public_key_to_address;
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::{self, Url};
use alloy::{hex, sol};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::{ConfigError, File};
use ecies::encrypt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

sol! {
    event SecretCreated(
        uint256 indexed secretId,
        address indexed owner,
        uint256 sizeLimit,
        uint256 endTimestamp,
        uint256 usdcDeposit,
        address[] selectedEnclaves
    );
}

struct ConfigManager {
    path: String,
}

// Config struct containing the secret store configuration parameters
#[derive(Debug, Deserialize)]
struct Config {
    stores: HashMap<Address, EnclaveInfo>,
}

#[derive(Clone, Deserialize, Debug)]
struct EnclaveInfo {
    public_key: String,
    store_external_ip: String,
}

impl ConfigManager {
    pub fn new(path: &String) -> ConfigManager {
        ConfigManager { path: path.clone() }
    }

    pub fn load_config(&self) -> Result<Config, ConfigError> {
        let settings = config::Config::builder()
            .add_source(File::with_name(self.path.as_str()))
            .build()?;
        settings.try_deserialize()
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Http rpc url
    #[clap(long, value_parser)]
    http_rpc_url: String,

    /// Secret create transaction hash
    #[clap(long, value_parser)]
    txn_hash: B256,

    /// Secret data file location
    #[clap(long, value_parser)]
    secret_data_file: String,

    /// User's private key to sign the data
    #[clap(long, value_parser)]
    user_private_hex: String,

    /// Secret store enclaves info configuration file
    #[clap(long, value_parser, default_value = "./stores_data.json")]
    secret_stores_data: String,
}

async fn inject_secret(
    enclave_address: Address,
    store_info: EnclaveInfo,
    secret_id: U256,
    secret_data_bytes: Vec<u8>,
    user_private_key: SigningKey,
) {
    let enclave_public_key = hex::decode(store_info.public_key);
    let Ok(enclave_public_key) = enclave_public_key else {
        eprintln!(
            "Failed to hex decode the enclave public key for address {}: {:?}\n",
            enclave_address,
            enclave_public_key.unwrap_err()
        );
        return;
    };

    // Encrypt secret data using the enclave 'secp256k1' public key
    let encrypted_secret_data_bytes = encrypt(&enclave_public_key, secret_data_bytes.as_slice());
    let Ok(encrypted_secret_data_bytes) = encrypted_secret_data_bytes else {
        eprintln!(
            "Failed to encrypt the secret data using public key of enclave {}: {:?}\n",
            enclave_address,
            encrypted_secret_data_bytes.unwrap_err()
        );
        return;
    };

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::Uint(secret_id, 256),
        DynSolValue::Bytes(encrypted_secret_data_bytes.clone()),
    ]);

    let data_hash = keccak256(token_list.abi_encode());

    // Sign the digest using user private key
    let sign = user_private_key.sign_prehash_recoverable(&data_hash.to_vec());
    let Ok((rs, v)) = sign else {
        eprintln!(
            "Failed to sign the secret data message using user private key for enclave {}: {:?}\n",
            enclave_address,
            sign.unwrap_err()
        );
        return;
    };
    let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

    let client = reqwest::Client::new();
    let req_url = store_info.store_external_ip + "/inject-secret";
    let request_json = json!({
        "secret_id": secret_id,
        "encrypted_secret_hex": hex::encode(encrypted_secret_data_bytes),
        "signature_hex": hex::encode(signature),
    });

    let response = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            client
                .post(req_url.clone())
                .json(&request_json.clone())
                .send()
                .await
        },
    )
    .await;
    let Ok(response) = response else {
        eprintln!(
            "Failed to send the request to secret store endpoint of enclave {}: {:?}\n",
            enclave_address,
            response.unwrap_err()
        );
        return;
    };

    if !response.status().is_success() {
        let response_body = response.text().await;
        let Ok(response_body) = response_body else {
            eprintln!(
                "Failed to parse the error response body from the secret inject response of enclave {}: {:?}\n",
                enclave_address,
                response_body.unwrap_err()
            );
            return;
        };

        eprintln!(
            "Failed to inject secret into the secret store with address {}: {:?}\n",
            enclave_address, response_body
        );
        return;
    }

    let secret_acknowledgement = response.json::<Value>().await;
    let Ok(secret_acknowledgement) = secret_acknowledgement else {
        eprintln!(
            "Failed to parse the acknowledgement json from the secret store response of enclave {}: {:?}\n",
            enclave_address,
            secret_acknowledgement.unwrap_err()
        );
        return;
    };

    println!(
        "Secret injected successfully into enclave {} with acknowledgement: {:?}",
        enclave_address, secret_acknowledgement
    );
    return;
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_manager = ConfigManager::new(&cli.secret_stores_data);
    let config = config_manager.load_config().unwrap();

    let secret_data_bytes =
        fs::read(cli.secret_data_file).context("Failed to read the secret data file")?;
    println!("Secret data in bytes: {:?}", secret_data_bytes);

    let user_private_key = SigningKey::from_slice(
        hex::decode(
            cli.user_private_hex
                .strip_prefix("0x")
                .unwrap_or(&cli.user_private_hex),
        )
        .context("Failed to decode the user private key hex")?
        .as_slice(),
    )
    .context("Invalid user signer key")?;

    let user_address = public_key_to_address(&user_private_key.verifying_key());

    let http_rpc_client = ProviderBuilder::new()
        .on_http(Url::parse(&cli.http_rpc_url).context("Failed to initialize http client")?);

    let Some(transaction_data) = http_rpc_client
        .get_transaction_by_hash(cli.txn_hash)
        .await
        .context("Failed to fetch transaction data")?
    else {
        return Err(anyhow!(
            "Transaction data empty corresponding to provided hash"
        ));
    };

    let Some(block_hash) = transaction_data.block_hash else {
        return Err(anyhow!(
            "Block hash not found corresponding to provided hash"
        ));
    };

    let Some(contract_address) = transaction_data.inner.to() else {
        return Err(anyhow!(
            "Contract address not found corresponding to provided hash"
        ));
    };

    let secrets_filter = Filter::new()
        .address(contract_address)
        .event("SecretCreated(uint256,address,uint256,uint256,uint256,address[])")
        .at_block_hash(block_hash);

    let secret_create_log = http_rpc_client
        .get_logs(&secrets_filter)
        .await
        .context("Failed to fetch secret create logs")?;
    let secret_create_log: Vec<&Log> = secret_create_log
        .iter()
        .filter(|&log| {
            log.transaction_hash
                .is_some_and(|hash| hash == cli.txn_hash)
        })
        .collect();

    if secret_create_log.is_empty() {
        return Err(anyhow!(
            "No secret create log found corresponding to transaction hash"
        ));
    }

    if secret_create_log.len() > 1 {
        return Err(anyhow!(
            "Multiple secret create logs found corresponding to transaction hash"
        ));
    }

    let log = secret_create_log.first().unwrap().to_owned();
    let decoded_log = SecretCreated::decode_log_data(log.data(), true)
        .context("Failed to decode secret created log")?;

    if user_address != decoded_log.owner {
        return Err(anyhow!("Invalid private key for the secret owner"));
    }

    if U256::from(secret_data_bytes.len()) > decoded_log.sizeLimit {
        return Err(anyhow!("Secret data length exceeds limit"));
    }

    let mut inject_set = JoinSet::new();

    for addr in decoded_log.selectedEnclaves {
        if !config.stores.contains_key(&addr) {
            eprintln!("Enclave with address {} not present in config data", addr);
            continue;
        }

        let store_info = config.stores.get(&addr).unwrap().clone();
        let secret_data_bytes_clone = secret_data_bytes.clone();
        let user_private_key_clone = user_private_key.clone();

        inject_set.spawn(async move {
            inject_secret(
                addr,
                store_info,
                decoded_log.secretId,
                secret_data_bytes_clone,
                user_private_key_clone,
            )
            .await
        });
    }

    let _ = inject_set.join_all().await;

    Ok(())
}
