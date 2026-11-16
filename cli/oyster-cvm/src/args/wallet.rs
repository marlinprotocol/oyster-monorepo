use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct WalletArgs {
    /// Wallet private key for transaction signing
    /// [Base64 OR Bech32 (with prefix 'suiprivkey') encoded 33-byte private key (flag || private_key) for Sui chain]
    #[arg(long, conflicts_with = "wallet_file")]
    wallet_private_key: Option<String>,

    /// Wallet private key file containing hex encoded private key
    #[arg(long, conflicts_with = "wallet_private_key")]
    wallet_file: Option<String>,
}

impl WalletArgs {
    pub fn load(&self) -> Result<Option<String>> {
        if let Some(ref key) = self.wallet_private_key {
            return Ok(Some(key.trim().into()));
        }

        if let Some(ref path) = self.wallet_file {
            // editors and `echo` leave a trailing newline in the file
            let key = fs::read_to_string(path).context("Failed to read private key file")?;
            let key = key.trim();
            if key.is_empty() {
                bail!("Private key file {path} is empty");
            }
            return Ok(Some(key.into()));
        }

        Ok(None)
    }

    /// Wallet flags to show in a suggested command, never contains the key itself.
    pub fn command_hint(&self) -> String {
        match self.wallet_file {
            Some(ref path) => format!("--wallet-file {path}"),
            None => "--wallet-private-key <key>".into(),
        }
    }

    pub fn load_required(&self) -> Result<String> {
        self.load().transpose().ok_or(anyhow!(
            "Wallet parameter is required, specify one of wallet-private-key or wallet-file."
        ))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_file_is_trimmed() {
        let path =
            std::env::temp_dir().join(format!("oyster-cvm-wallet-test-{}", std::process::id()));
        fs::write(&path, "  abcd1234\r\n\n").unwrap();
        let args = WalletArgs {
            wallet_private_key: None,
            wallet_file: Some(path.to_string_lossy().into_owned()),
        };
        assert_eq!(args.load().unwrap().unwrap(), "abcd1234");

        fs::write(&path, "\n").unwrap();
        assert!(args.load().is_err());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn command_hint_never_contains_the_key() {
        let args = WalletArgs {
            wallet_private_key: Some("abcd1234".into()),
            wallet_file: None,
        };
        assert!(!args.command_hint().contains("abcd1234"));
    }
}
