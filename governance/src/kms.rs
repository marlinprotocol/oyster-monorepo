use alloy::primitives::{B256, FixedBytes, keccak256};
use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};

use crate::config::get_config;

pub type SigningPublicKey = FixedBytes<64>;
#[async_trait]
pub trait KMS {
    async fn get_persistent_secret_key(&self) -> Result<SigningPrivateKey>;
    async fn get_persistent_public_key(&self) -> Result<SigningPublicKey>;

    async fn get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey>;
    async fn get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey>;
}

#[derive(Debug, Clone, Default)]
pub struct DirtyKMS;

#[async_trait]
impl KMS for DirtyKMS {
    async fn get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        let sk_hex = get_config()?.init_dirty_key;
        let raw: Vec<u8> = hex::decode(sk_hex)?;
        Ok(SigningPrivateKey::from_slice(&raw)?)
    }

    async fn get_persistent_public_key(&self) -> Result<SigningPublicKey> {
        Ok(self.get_persistent_secret_key().await?.public_key())
    }

    async fn get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey> {
        // 1) Master secret (32 bytes)
        let master = self.get_persistent_secret_key().await?;
        let master_bytes = master.to_bytes().to_vec();

        let mut input = Vec::with_capacity(12 + 32 + 32);
        input.extend_from_slice(b"proposal-ecies");
        input.extend_from_slice(&master_bytes);
        input.extend_from_slice(proposal_hash.as_slice());
        let digest: B256 = keccak256(&input);

        let private_key: &[u8; 32] = digest.as_slice().try_into().unwrap();

        let enc_sk =
            EncryptionPrivateKey::parse(private_key).map_err(|e| anyhow!(" failed: {e}"))?;
        Ok(enc_sk)
    }

    async fn get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey> {
        Ok(EncryptionPublicKey::from_secret_key(
            &self.get_proposal_secret_key(proposal_hash).await?,
        ))
    }
}
