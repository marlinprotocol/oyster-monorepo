use alloy::primitives::{B256, Bytes, FixedBytes, keccak256};
use alloy::signers::SignerSync;
use alloy::signers::k256::sha2::{Digest, Sha256};
use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
use alloy::sol_types::SolValue;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};

use crate::config::get_config;

pub type SigningPublicKey = FixedBytes<64>;
#[async_trait]
pub trait KMS {
    async fn get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        // You can add invariants, logging, metrics, caching, etc. here
        log::debug!("Fetching persistent secret key");
        self._get_persistent_secret_key().await
    }

    async fn get_persistent_public_key(&self) -> Result<SigningPublicKey> {
        log::debug!("Fetching persistent public key");
        self._get_persistent_public_key().await
    }

    async fn get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey> {
        log::debug!(
            "Fetching proposal secret key for proposal: {}",
            hex::encode(proposal_hash)
        );
        self._get_proposal_secret_key(proposal_hash).await
    }

    async fn get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey> {
        log::debug!(
            "Fetching proposal public key for proposal: {}",
            hex::encode(proposal_hash)
        );
        self._get_proposal_public_key(proposal_hash).await
    }

    // ---------- required “internal” methods (override these) ----------

    /// Implementors MUST return the persistent signing secret key.
    async fn _get_persistent_secret_key(&self) -> Result<SigningPrivateKey>;

    /// Implementors MUST return the persistent signing public key.
    async fn _get_persistent_public_key(&self) -> Result<SigningPublicKey>;

    /// Implementors MUST return the per-proposal encryption secret key.
    async fn _get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey>;

    /// Implementors MUST return the per-proposal encryption public key.
    async fn _get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey>;

    async fn get_proposal_secret_bytes(&self, proposal_hash: B256) -> Result<Bytes> {
        let sk = self.get_proposal_secret_key(proposal_hash).await?;
        Ok(sk.serialize().into())
    }

    async fn generate_kms_sig(
        &self,
        image_id: B256,
        enclave_pubkey: Bytes,
        proposal_id: B256,
    ) -> Result<Bytes> {
        let uri = format!(
            "/derive/secp256k1/public?image_id={}&path={}_result",
            hex::encode(image_id),
            hex::encode(proposal_id),
        );

        log::debug!("uri: {}", uri);

        let uri_bytes: Vec<u8> = uri.as_bytes().to_vec();
        let message = (uri_bytes, enclave_pubkey.clone()).abi_encode_packed();
        let digest: B256 = {
            let h = Sha256::digest(&message); // returns generic-array [u8; 32]
            B256::from_slice(&h)
        };
        log::debug!("message: {}", hex::encode(digest));

        let signature = self
            .get_persistent_secret_key()
            .await?
            .sign_hash_sync(&digest)?
            .as_bytes();

        log::debug!("kms signature: {}", hex::encode(signature));

        Ok(signature.into())
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirtyKMS;

#[async_trait]
impl KMS for DirtyKMS {
    async fn _get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        let sk_hex = get_config()?.init_dirty_key;
        let raw: Vec<u8> = hex::decode(sk_hex)?;
        Ok(SigningPrivateKey::from_slice(&raw)?)
    }

    async fn _get_persistent_public_key(&self) -> Result<SigningPublicKey> {
        Ok(self.get_persistent_secret_key().await?.public_key())
    }

    async fn _get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey> {
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

    async fn _get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey> {
        Ok(EncryptionPublicKey::from_secret_key(
            &self.get_proposal_secret_key(proposal_hash).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
    use anyhow::Result;

    use crate::kms::{DirtyKMS, KMS};

    #[tokio::test]
    async fn test_kms_sig_generation() -> Result<()> {
        let sig = DirtyKMS::default()
            .generate_kms_sig(
                "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01".parse()?,
                SigningPrivateKey::random().public_key().to_vec().into(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".parse()?,
            )
            .await?;
        println!("{}", hex::encode(sig));
        Ok(())
    }
}
