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
use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
use lazy_static::lazy_static;
use libsodium_sys::{crypto_box_SEALBYTES, crypto_box_seal, sodium_init};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::types::Platform;

use super::pcr::{PcrArgs, PCRS_BASE_BLUE_V1_0_0_AMD64, PCRS_BASE_BLUE_V1_0_0_ARM64};

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
    pub fn load(self, preset: String, arch: Platform, debug: bool) -> Result<Option<String>> {
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

        init_params.append(&mut self.init_params.unwrap_or_default());

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
        let pcrs = self
            .pcrs
            .load()
            .context("Failed to load PCRs")?
            .map(Result::Ok)
            .unwrap_or(match preset.as_str() {
                "blue" => match arch {
                    Platform::AMD64 => Ok((
                        PCRS_BASE_BLUE_V1_0_0_AMD64.0.into(),
                        PCRS_BASE_BLUE_V1_0_0_AMD64.1.into(),
                        PCRS_BASE_BLUE_V1_0_0_AMD64.2.into(),
                    )),
                    Platform::ARM64 => Ok((
                        PCRS_BASE_BLUE_V1_0_0_ARM64.0.into(),
                        PCRS_BASE_BLUE_V1_0_0_ARM64.1.into(),
                        PCRS_BASE_BLUE_V1_0_0_ARM64.2.into(),
                    )),
                },
                "debug" => Ok((
                    hex::encode([0u8; 48]),
                    hex::encode([0u8; 48]),
                    hex::encode([0u8; 48]),
                )),
                _ => Err(anyhow!("PCRs are required")),
            })?;

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
                    if debug {
                        // attempting to use encrypted init params in debug mode
                        // error out since it is not safe
                        return Err(anyhow!(
                            "Refused to allow encrypted init params in debug mode enclaves. It is not safe to use encrypted init params in debug mode since it can then be decrypted and exported by other debug enclaves."
                        ));
                    }

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

#[derive(Serialize, Deserialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    should_attest: bool,
    should_decrypt: bool,
}

#[derive(Serialize, Deserialize)]
pub struct InitParamsList {
    pub digest: String, // base64 encoded
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
            42161,
            r#"
                {
                    "kms_endpoint": "arbone-v2.kms.box:1100",
                    "pcr0": "439e85acd45a7d476e940346aa1e125ef06665efdd403bb056e89a4dbb3ba7bb85b853e2a70fe434d05e3daf75ef63ff",
                    "pcr1": "3dc2602d18944028b4705c2b46c5d6efd73cba3c58d09deccc073075c68a4ebac36e5368eb0921c7b4c699f4ae03a1e5",
                    "pcr2": "ee6041a503a1c17cdcf4b5c18bd82d2f5c934b2024e61c2b97b81416bab9cb72bcdf42a290f82f5053746fb80fa2b062",
                    "user_data": "544d4b69000100009293c430807c79fea118542ce3e2af018fc76edb82145192344be25beaaefde850b53843e9373f13fbd5f7e13f67fac11e2a5b15c46099587116f84567ab75e6abf4953cebc1b5096adc8f9705a6dce7c10f6b591310e6b3b16ae3e60b6766f2a114ff2d609c176666edc8d568e4a661f527ba7996c005830bd7c2a21b60e42832f07f0951b49703e8564e5a61a892c8f4755cbd7361c4506c38084df743fd0b1244d5a0d6e93e9f27cc0d1a10792cb255e9c75c85872161f772574bebbc9b2c4352b4685b3ee2cd161fb301fb09d4efd8a87ad5918216fc4a41d542576b3d0bfabcaa141b15b63c9292c430868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741da01b87b22636f6e646974696f6e223a7b22636861696e223a312c22636f6e646974696f6e54797065223a22636f6e7472616374222c22636f6e747261637441646472657373223a22307843653735446232423235453061393636423634453337433232343646373065336133464630393439222c2266756e6374696f6e416269223a7b22696e70757473223a5b7b22696e7465726e616c54797065223a2261646472657373222c226e616d65223a22222c2274797065223a2261646472657373227d5d2c226e616d65223a2269735665726966696564222c226f757470757473223a5b7b22696e7465726e616c54797065223a22626f6f6c222c226e616d65223a22222c2274797065223a22626f6f6c227d5d2c2273746174654d75746162696c697479223a2276696577222c2274797065223a2266756e6374696f6e227d2c226d6574686f64223a2269735665726966696564222c22706172616d6574657273223a5b223a7573657241646472657373225d2c2272657475726e56616c756554657374223a7b22636f6d70617261746f72223a223d3d222c2276616c7565223a747275657d7d2c2276657273696f6e223a22312e302e30227dc441b4fc1206b3290a1da56ab118df0cf9e660c1bb069ae71edf32f0f7d4743f51061e861476e8a67d2b92d42559af3b6aac310785408a658d53765395ac8be2783c1c"
                }
            "#,
        );
        root_servers
    };
}
