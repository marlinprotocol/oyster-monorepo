use std::{
    fs,
    path::{Component, PathBuf},
};

use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Args;
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
        if self.init_params.is_none() && self.docker_compose.is_none() {
            return Ok(None);
        };

        let mut init_params = self
            .docker_compose
            .map(|x| vec![format!("docker-compose.yml:1:0:file:{x}")])
            .unwrap_or(vec![]);
        init_params.append(&mut self.init_params.unwrap_or(vec![]));

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
        let pk = fetch_encryption_key(
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

fn fetch_encryption_key(
    endpoint: &str,
    pcr0: &str,
    pcr1: &str,
    pcr2: &str,
    user_data: &str,
) -> Result<[u8; 32]> {
    Ok(ureq::get(endpoint.to_owned() + "/derive/x25519/public")
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
        .context("failed to parse reponse")?)
}
