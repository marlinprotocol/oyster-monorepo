use std::{
    convert::identity,
    fs::{create_dir_all, read_to_string, write},
    path::{Component, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use libsodium_sys::{
    crypto_box_SEALBYTES, crypto_box_seal_open, crypto_scalarmult_base, sodium_init,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Args {
    /// Init params file
    #[arg(long, default_value = "/app/init-params")]
    init_params_path: String,

    /// Derive server endpoint
    #[arg(long, default_value = "http://127.0.0.1:1100")]
    derive_endpoint: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run().inspect_err(|e| error!("{e:?}"))
}

fn run() -> Result<()> {
    // parse args
    let args = Args::parse();

    // SAFETY: no params, return value is checked properly
    if unsafe { sodium_init() } < 0 {
        bail!("failed to init libsodium");
    }

    // parse init params
    let init_params_str = read_to_string(args.init_params_path)
        .context("failed to read init params, should never happen")?;
    if init_params_str == "" {
        // ignore empty params
        info!("empty init params");
        return Ok(());
    }
    let init_params = serde_json::from_str::<InitParamsList>(&init_params_str)
        .context("failed to parse init params")?;

    // fetch key
    let sk =
        fetch_encryption_key(&args.derive_endpoint).context("failed to fetch encryption key")?;
    let mut pk = [0u8; 32];

    // SAFETY: pk and sk are the right size
    // cannot fail, ignore return value
    unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()) };

    let digest = init_params
        .params
        .into_iter()
        .map(|init_param| -> Result<Option<[u8; 32]>> {
            info!(init_param.path, "processing");

            // everything should be normal components, no root or current or parent dirs
            if PathBuf::from(&init_param.path)
                .components()
                .any(|x| !matches!(x, Component::Normal(_)))
            {
                bail!("invalid path")
            }

            let path = PathBuf::from("/init-params/".to_owned() + &init_param.path);

            // we want to fail closed, hence detect errors as well
            if path
                .try_exists()
                .context("failed to check if path exists")?
            {
                bail!("file already exists");
            }

            let mut contents = BASE64_STANDARD
                .decode(init_param.contents.as_bytes())
                .context("failed to decode contents")?;

            if init_param.should_decrypt {
                if contents.len() > 65535 {
                    bail!("invalid content length");
                }

                // SAFETY: contents is big enough for the decrypted message
                // in-place decryption is supported by libsodium
                // pk and sk are the right size
                let res = unsafe {
                    crypto_box_seal_open(
                        contents.as_mut_ptr(),
                        contents.as_ptr(),
                        contents.len() as u64,
                        pk.as_ptr(),
                        sk.as_ptr(),
                    )
                };
                if res != 0 {
                    bail!("failed to decrypt");
                }

                // successfully decrypted, truncate seal
                contents.truncate(contents.len() - crypto_box_SEALBYTES as usize);
            }

            create_dir_all(path.parent().ok_or(anyhow!("failed to get parent"))?)
                .context("failed to create dirs")?;
            write(&path, &contents).context("failed to write contents")?;

            if init_param.should_attest {
                let mut hasher = Sha256::new();
                hasher.update(path.as_os_str().len().to_le_bytes());
                hasher.update(path.as_os_str().as_encoded_bytes());
                hasher.update(contents.len().to_le_bytes());
                hasher.update(contents.as_slice());

                return Ok(Some(hasher.finalize().into()));
            } else {
                return Ok(None);
            }
        })
        // will short circuit if anything errors
        .collect::<Result<Vec<_>>>()
        .context("failed to process init params")?
        .into_iter()
        // filter out Nones
        .filter_map(identity)
        // accumulate futher into a single hash
        .fold(Sha256::new(), |mut hasher, param_hash| {
            hasher.update(param_hash);
            hasher
        })
        .finalize();
    

    if digest.as_slice()
        != BASE64_STANDARD
            .decode(init_params.digest)
            .context("failed to decode digest")?
            .as_slice()
    {
        bail!("digest mismatch");
    }

    Ok(())
}

fn fetch_encryption_key(endpoint: &str) -> Result<[u8; 32]> {
    Ok(ureq::get(endpoint.to_owned() + "/derive/x25519")
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

#[derive(Deserialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    #[serde(default = "_default_true")]
    should_attest: bool,
    #[serde(default)]
    should_decrypt: bool,
}

#[derive(Deserialize)]
struct InitParamsList {
    digest: String, // base64 encoded
    params: Vec<InitParam>,
}

// blergh
const fn _default_true() -> bool {
    true
}
