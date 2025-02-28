use std::fs;

use anyhow::{Context, Result};
use clap::Args;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct WalletArgs {
    /// Wallet private key for transaction signing
    #[arg(long, conflicts_with = "wallet_file")]
    wallet_private_key: Option<String>,

    /// Wallet private key file containing hex encoded private key
    #[arg(long, conflicts_with = "wallet_private_key")]
    wallet_file: Option<String>,
}

impl WalletArgs {
    pub fn load(&self) -> Result<Option<String>> {
        if let Some(ref key) = self.wallet_private_key {
            return Ok(Some(key.into()));
        }

        if let Some(ref path) = self.wallet_file {
            return Ok(Some(
                fs::read_to_string(path).context("Failed to read private key file")?,
            ));
        }

        Ok(None)
    }
}
