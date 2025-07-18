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
use k256::sha2::Sha384;
use lazy_static::lazy_static;
use libsodium_sys::{crypto_box_SEALBYTES, crypto_box_seal, sodium_init};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{args::pcr::preset_to_pcr_preset, types::Platform};

use super::pcr::PcrArgs;

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

    /// KMS response signature verification key
    #[arg(long)]
    pub kms_verification_key: Option<String>,

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
        // if debug flag is true, uses zero pcrs
        let pcrs = self
            .pcrs
            .load_required(preset_to_pcr_preset(&preset, &arch, debug))
            .context("Failed to load PCRs")?;

        // calculate pcr16 by extending the digest onto zero pcrs
        let mut pcr_hasher = Sha384::new();
        pcr_hasher.update([0u8; 48]);
        pcr_hasher.update(digest);
        let pcr16: [u8; 48] = pcr_hasher.finalize().into();

        // calculate the image id
        let mut hasher = Sha256::new();
        // bitflags denoting what pcrs are part of the computation
        // this one has 0, 1, 2 and 16
        hasher.update(&((1u32 << 0) | (1 << 1) | (1 << 2) | (1 << 16)).to_be_bytes());
        hasher.update(hex::decode(pcrs.0).context("failed to decode PCR")?);
        hasher.update(hex::decode(pcrs.1).context("failed to decode PCR")?);
        hasher.update(hex::decode(pcrs.2).context("failed to decode PCR")?);
        hasher.update(pcr16);
        let image_id: [u8; 32] = hasher.finalize().into();
        info!(image_id = hex::encode(image_id), "Computed image id");
        // fetch key
        let pk = fetch_encryption_key_with_pcr(
            self.kms_endpoint
                .as_ref()
                .unwrap_or(&"http://image-v4.kms.box:1101".into()),
            self.kms_verification_key
                .as_ref()
                .unwrap_or(&"14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276".into()),
            &hex::encode(image_id),
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
    kms_verification_key: &str,
    image_id: &str,
) -> Result<[u8; 32]> {
    let uri = format!(
        "/derive/x25519/public?image_id={}&path=oyster.init-params",
        image_id
    );
    let mut response = ureq::get(endpoint.to_owned() + uri.as_str())
        .call()
        .context("failed to call derive server")?;

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

    if pubkey != kms_verification_key.to_lowercase() {
        bail!("signature verifaction failed: unexpected signer");
    }

    body_bytes
        .as_slice()
        .try_into()
        .context("failed to parse reponse")
}

lazy_static! {
    static ref KMS_ROOT_SERVERS: HashMap<u64, String> = {
        let mut root_servers = HashMap::new();
        root_servers.insert(
            42161,
            serde_json::json!({
                "kms_endpoint": "arbone-v4.kms.box:1100",
                "kms_pubkey": "5ee189d3b990c284ebfe7fc4c2e1cecdb2a6908d0a1aa152592d30066061b92c"
            })
            .to_string(),
        );
        root_servers
    };
}
