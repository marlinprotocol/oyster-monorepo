use crate::kms::kms::KMS;
use alloy::{primitives::B256, signers::local::PrivateKeySigner as SigningPrivateKey};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use ecies::SecretKey as EncryptionPrivateKey;

pub struct OysterKms;

#[async_trait]
impl KMS for OysterKms {
    async fn _get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        let resp_bytes = reqwest::get("http://127.0.0.1:1100/derive/secp256k1?path=signing-server")
            .await?
            .bytes()
            .await?;

        let key_bytes: [u8; 32] = resp_bytes[..32]
            .try_into()
            .expect("response body shorter than 32 bytes");

        let sec = SigningPrivateKey::from_bytes(&B256::from_slice(&key_bytes))?;

        Ok(sec)
    }

    async fn _get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey> {
        let resp_bytes = reqwest::get(format!(
            "http://127.0.0.1:1100/derive/secp256k1?path={}",
            proposal_hash
        ))
        .await?
        .bytes()
        .await?;

        let key_bytes: [u8; 32] = resp_bytes[..32]
            .try_into()
            .expect("response body shorter than 32 bytes");

        let sec = EncryptionPrivateKey::parse(&key_bytes)
            .map_err(|_| anyhow!("Invalid key length, expected 32 bytes"))?;

        Ok(sec)
    }

    async fn _get_persistent_encryption_secret_key(&self) -> Result<EncryptionPrivateKey> {
        let resp_bytes = reqwest::get(format!(
            "http://127.0.0.1:1100/derive/secp256k1?path={}",
            "encryption_key"
        ))
        .await?
        .bytes()
        .await?;

        let key_bytes: [u8; 32] = resp_bytes[..32]
            .try_into()
            .expect("response body shorter than 32 bytes");

        let sec = EncryptionPrivateKey::parse(&key_bytes)
            .map_err(|_| anyhow!("Invalid key length, expected 32 bytes"))?;

        Ok(sec)
    }
}
