use std::{
    collections::HashMap,
    fs,
    path::{Component, PathBuf},
};

use alloy::primitives::Address;
use alloy::{
    hex::FromHex,
    signers::k256::sha2::{Digest, Sha256},
};
use anyhow::{bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
use lazy_static::lazy_static;
use libsodium_sys::{crypto_box_SEALBYTES, crypto_box_seal, sodium_init};
use serde::Serialize;
use tracing::info;

use super::pcr::{PcrArgs, PCRS_BASE_BLUE_V1_0_0_ARM64};

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct InitParamsArgs {
    /// Base64 encoded init params
    #[arg(short = 'e', long, conflicts_with = "init_params")]
    pub init_params_encoded: Option<String>,

    /// Init params list, supports the following forms:
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>`
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
    #[arg(short = 'i', long)]
    pub init_params: Option<Vec<String>>,

    /// KMS endpoint for fetching public key for encryption
    #[arg(short = 'k', long)]
    pub kms_endpoint: Option<String>,

    /// Expected PCRs of the decryptor
    #[command(flatten)]
    pub pcrs: PcrArgs,

    /// Encalve verifier contract address
    #[arg(long, requires = "chain_id")]
    pub contract_address: Option<String>,

    /// Chain ID for KMS contract root server
    #[arg(long, requires = "contract_address")]
    pub chain_id: Option<u64>,

    /// Docker compose file defining services to run,
    /// set as first init param
    #[arg(long)]
    pub docker_compose: Option<String>,
}

impl InitParamsArgs {
    pub fn load(self) -> Result<Option<String>> {
        // check for encoded params
        if self.init_params_encoded.is_some() {
            return Ok(self.init_params_encoded.clone());
        }

        // check if there are any init params
        if self.init_params.is_none()
            && self.docker_compose.is_none()
            && self.contract_address.is_none()
        {
            return Ok(None);
        };

        let mut init_params = self
            .docker_compose
            .map(|x| vec![format!("docker-compose.yml:1:0:file:{x}")])
            .unwrap_or_default();
        init_params.append(&mut self.init_params.unwrap_or_default());

        if let Some(address) = self.contract_address {
            if let Err(_) = Address::from_hex(&address) {
                bail!("invalid contract address");
            }
            init_params.push(format!("contract-address:1:0:utf8:{}", address));

            let Some(root_server_str) = KMS_ROOT_SERVERS.get(&self.chain_id.unwrap()) else {
                bail!("unknown chain id");
            };
            init_params.push(format!(
                "root-server-config.json:1:0:utf8:{}",
                root_server_str
            ));
        }

        // encoding has to be done

        // SAFETY: no params, return value is checked properly
        if unsafe { sodium_init() } < 0 {
            bail!("failed to init libsodium");
        }

        // process in two passes since digest is needed to fetch public key

        // compute digest
        let digest = init_params
            .iter()
            .map(|param| {
                // extract components
                let param_components = param.splitn(5, ":").collect::<Vec<_>>();
                let should_attest = param_components[1] == "1";

                // everything should be normal components, no root or current or parent dirs
                if PathBuf::from(param_components[0])
                    .components()
                    .any(|x| !matches!(x, Component::Normal(_)))
                {
                    bail!("invalid path")
                }

                if !should_attest {
                    return Ok(None);
                }

                let enclave_path = PathBuf::from("/init-params/".to_owned() + param_components[0]);
                let should_encrypt = param_components[2] == "1";
                let contents = match param_components[3] {
                    "utf8" => param_components[4].as_bytes().to_vec(),
                    "file" => fs::read(param_components[4]).context("failed to read file")?,
                    _ => bail!("unknown param type"),
                };

                info!(
                    path = param_components[0],
                    should_attest, should_encrypt, "digest"
                );

                // compute individual digest
                let mut hasher = Sha256::new();
                hasher.update(enclave_path.as_os_str().len().to_le_bytes());
                hasher.update(enclave_path.as_os_str().as_encoded_bytes());
                hasher.update(contents.len().to_le_bytes());
                hasher.update(contents);

                Ok(Some(hasher.finalize()))
            })
            .collect::<Result<Vec<_>>>()
            .context("failed to compute individual digest")?
            .into_iter()
            .flatten()
            // accumulate futher into a single hash
            .fold(Sha256::new(), |mut hasher, param_hash| {
                hasher.update(param_hash);
                hasher
            })
            .finalize();

        info!(digest = hex::encode(digest), "Computed digest");

        // load pcrs
        // use pcrs of the blue base image by default
        let pcrs = self.pcrs.load().context("Failed to load PCRs")?.unwrap_or((
            PCRS_BASE_BLUE_V1_0_0_ARM64.0.into(),
            PCRS_BASE_BLUE_V1_0_0_ARM64.1.into(),
            PCRS_BASE_BLUE_V1_0_0_ARM64.2.into(),
        ));

        // fetch key
        let pk = fetch_encryption_key_with_pcr(
            self.kms_endpoint
                .as_ref()
                .unwrap_or(&"http://image-v2.kms.box:1101".into()),
            &pcrs.0,
            &pcrs.1,
            &pcrs.2,
            &hex::encode(digest),
        )
        .context("failed to fetch key")?;

        // prepare init params
        let params = init_params
            .iter()
            .map(|param| {
                // extract components
                let param_components = param.splitn(5, ":").collect::<Vec<_>>();
                let should_attest = param_components[1] == "1";
                let should_encrypt = param_components[2] == "1";
                let contents = match param_components[3] {
                    "utf8" => param_components[4].as_bytes().to_vec(),
                    "file" => fs::read(param_components[4]).context("failed to read file")?,
                    _ => bail!("unknown param type"),
                };

                info!(
                    path = param_components[0],
                    should_attest, should_encrypt, "param"
                );

                // encrypt if needed
                let final_contents = if should_encrypt {
                    let mut final_contents =
                        vec![0u8; contents.len() + crypto_box_SEALBYTES as usize];
                    // SAFETY: buffer is big enough for the encrypted message
                    // pk is the right size
                    unsafe {
                        crypto_box_seal(
                            final_contents.as_mut_ptr(),
                            contents.as_ptr(),
                            contents.len() as u64,
                            pk.as_ptr(),
                        )
                    };
                    final_contents
                } else {
                    contents
                };

                let init_param = InitParam {
                    path: param_components[0].to_owned(),
                    contents: BASE64_STANDARD.encode(final_contents),
                    should_attest,
                    should_decrypt: should_encrypt,
                };

                Ok(init_param)
            })
            .collect::<Result<Vec<_>>>()
            .context("failed to build init params")?;

        // create final init params
        let init_params = InitParamsList {
            digest: BASE64_STANDARD.encode(digest),
            params,
        };

        let json = serde_json::to_string_pretty(&init_params)
            .context("failed to serialize init params")?;

        Ok(Some(BASE64_STANDARD.encode(json)))
    }
}

#[derive(Serialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    should_attest: bool,
    should_decrypt: bool,
}

#[derive(Serialize)]
struct InitParamsList {
    digest: String, // base64 encoded
    params: Vec<InitParam>,
}

fn fetch_encryption_key_with_pcr(
    endpoint: &str,
    pcr0: &str,
    pcr1: &str,
    pcr2: &str,
    user_data: &str,
) -> Result<[u8; 32]> {
    ureq::get(endpoint.to_owned() + "/derive/x25519/public")
        .query("pcr0", pcr0)
        .query("pcr1", pcr1)
        .query("pcr2", pcr2)
        .query("user_data", user_data)
        .query("path", "oyster.init-params")
        .call()
        .context("failed to call derive server")?
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?
        .as_slice()
        .try_into()
        .context("failed to parse reponse")
}

// TODO fill store KMS details
lazy_static! {
    static ref KMS_ROOT_SERVERS: HashMap<u64, &'static str> = {
        let mut root_servers = HashMap::new();
        root_servers.insert(
            31337,
            r#"
                {
                    "kms_endpoint": "image-v2.kms.box:1101",
                    "pcr1": "cb7ebc13d527e9cf9cc271b0d816c72a5bfa685ae56118ce4986fa82b8b9aac8b851206539a6c4600ad77566aa15bd0e",
                    "pcr2": "3b26340a10ac3a5494139fed12bc30028017b72dabfb78a38763bd21ea67bbfe03214e7ce628c2952cfa2ff478f370ba",
                    "pcr3": "0d128997bfc8ef24a2aa1ecec60c61e48eda9b439f8662d41eb38d8f0ba0401367778a5f8804127c591d824d5c3ed617",
                    "user_data": "544d4b69000100009293c4308e0ebc7f830be9a963f343358c4875d67c36eb1dc0c3250cb9438a43f0399ed4fc7e0b80ccb99b106136e06bbaecb90bc460843d33b632beb3537a7d1c42531ad1b43bce0015ba7e7fb7ed82fed9a0d200ac11dc646ca22b743daec9baa39d689c350a3e70ce85979e856e9cac3c31f45febe28510360beb78495932a6e06c2a5fd6caa0adc9dff0fef20d9ff4916199bcbcc450cf36031706fbe58b82fcf808e76f801924ec66a3ea5bcaec0fb33619cf5df6314b43eca506a25392b1e042126a63744f35bd39403c6d73e81a4efaf0e0251563ee3eacc2ce419ae5a1c139d5d321761a9292c430868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741da01b87b22636f6e646974696f6e223a7b22636861696e223a312c22636f6e646974696f6e54797065223a22636f6e7472616374222c22636f6e747261637441646472657373223a22307843374430383443326536424341633030374433424146433431353438356133383038303343306265222c2266756e6374696f6e416269223a7b22696e70757473223a5b7b22696e7465726e616c54797065223a2261646472657373222c226e616d65223a22222c2274797065223a2261646472657373227d5d2c226e616d65223a2269735665726966696564222c226f757470757473223a5b7b22696e7465726e616c54797065223a22626f6f6c222c226e616d65223a22222c2274797065223a22626f6f6c227d5d2c2273746174654d75746162696c697479223a2276696577222c2274797065223a2266756e6374696f6e227d2c226d6574686f64223a2269735665726966696564222c22706172616d6574657273223a5b223a7573657241646472657373225d2c2272657475726e56616c756554657374223a7b22636f6d70617261746f72223a223d3d222c2276616c7565223a747275657d7d2c2276657273696f6e223a22312e302e30227dc441cd0ad8db7d03074a07437a39025a8deea6a72c433dedc45375b95d28257dc0300ae70507050f75c5d5c31c50b167bdde4c06ac789b22641defe91de9442fd74d1b"
                }
            "#,
        );
        root_servers
    };
}
