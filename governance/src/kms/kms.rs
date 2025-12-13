use alloy::primitives::{Address, B256, Bytes, FixedBytes, keccak256};
use alloy::signers::SignerSync;
use alloy::signers::k256::sha2::{Digest, Sha256};
use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
use alloy::sol_types::SolValue;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use dotenvy::dotenv;
use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};

pub type SigningPublicKey = FixedBytes<64>;

// This trait defines a common interface for KMS modules to be implemented
#[async_trait]
pub trait KMS {
    /// Returns the secret signing key that will be used to sign the voting result. This key be be persistent
    async fn get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        log::debug!("Fetching persistent secret key");
        self._get_persistent_secret_key().await
    }

    /// Returns the public key of the assiciated secret signing key that will be used to sign the voting result. This key be be persistent
    async fn get_persistent_public_key(&self) -> Result<SigningPublicKey> {
        log::debug!("Fetching persistent public key");
        self._get_persistent_public_key().await
    }

    async fn get_persistant_signing_address(&self) -> Result<Address> {
        let sk: SigningPrivateKey = self._get_persistent_secret_key().await?;
        Ok(sk.address())
    }

    /// Returns the secret key with which votes must be encrypted for a proposal.
    async fn get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey> {
        log::debug!(
            "Fetching proposal secret key for proposal: {}",
            hex::encode(proposal_hash)
        );
        self._get_proposal_secret_key(proposal_hash).await
    }

    /// Returns the public key assiciated with secret key with which votes must be encrypted for a proposal.
    async fn get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey> {
        log::debug!(
            "Fetching proposal public key for proposal: {}",
            hex::encode(proposal_hash)
        );
        self._get_proposal_public_key(proposal_hash).await
    }

    async fn get_persistent_encryption_secret_key(&self) -> Result<EncryptionPrivateKey> {
        log::debug!("Fetching persistent encryption secret key",);
        self._get_persistent_encryption_secret_key().await
    }

    async fn get_persistent_encryption_public_key(&self) -> Result<EncryptionPublicKey> {
        log::debug!("Fetching persistent encryption public key",);
        self._get_persistent_encryption_public_key().await
    }

    async fn _get_persistent_public_key(&self) -> Result<SigningPublicKey> {
        log::debug!("Fetching persistent public key for proposal",);
        Ok(self.get_persistent_secret_key().await?.public_key())
    }
    async fn _get_proposal_public_key(&self, proposal_hash: B256) -> Result<EncryptionPublicKey> {
        Ok(EncryptionPublicKey::from_secret_key(
            &self.get_proposal_secret_key(proposal_hash).await?,
        ))
    }
    async fn _get_persistent_encryption_public_key(&self) -> Result<EncryptionPublicKey> {
        Ok(EncryptionPublicKey::from_secret_key(
            &self._get_persistent_encryption_secret_key().await?,
        ))
    }
    // ---------- required “internal” methods (override these) ----------

    /// Implementors MUST return the persistent signing secret key.
    async fn _get_persistent_secret_key(&self) -> Result<SigningPrivateKey>;

    /// Implementors MUST return the per-proposal encryption secret key.
    async fn _get_proposal_secret_key(&self, proposal_hash: B256) -> Result<EncryptionPrivateKey>;

    // Implementors MUST return the persistent encryption secret key.
    async fn _get_persistent_encryption_secret_key(&self) -> Result<EncryptionPrivateKey>;

    async fn get_proposal_secret_bytes(&self, proposal_hash: B256) -> Result<Bytes> {
        let sk = self.get_proposal_secret_key(proposal_hash).await?;
        Ok(sk.serialize().into())
    }

    /// Generates a KMS signature over the given attestation inputs.
    ///
    /// This signs a message derived from the `image_id`, `enclave_pubkey`, and
    /// `proposal_id` using the configured KMS backend and returns the raw
    /// signature bytes.
    ///
    /// # Arguments
    ///
    /// * `image_id` - Identifier of the guest image / circuit being attested.
    /// * `enclave_pubkey` - Public key of the enclave or prover, encoded as bytes.
    /// * `proposal_id` - Identifier of the governance proposal this attestation
    ///   is bound to.
    ///
    /// # Errors
    ///
    /// Returns an error if the KMS request fails, the signature cannot be
    /// produced, or the underlying transport encounters an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use alloy::primitives::{B256, Bytes};
    /// use governance::kms::kms::KMS;
    ///
    /// # async fn example<K: KMS + Send + Sync>(kms: K) -> anyhow::Result<()> {
    /// #     let image_id = B256::ZERO;
    /// #     let enclave_pubkey = "0x1234".parse()?;
    /// #     let proposal_id = B256::ZERO;
    /// #
    ///     let sig = kms
    ///         .generate_kms_sig(image_id, enclave_pubkey, proposal_id)
    ///         .await?;
    ///     println!("KMS signature: {sig:?}");
    /// #
    /// #     Ok(())
    /// # }
    /// ```
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

/// Sample implementation of KMS service. This should be only used during local testing.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyKMS;

#[async_trait]
impl KMS for DirtyKMS {
    async fn _get_persistent_encryption_secret_key(&self) -> Result<EncryptionPrivateKey> {
        dotenv().ok();
        let sk_hex = std::env::var("DIRTY_KMS_HEX")?;
        let raw: Vec<u8> = hex::decode(sk_hex)?;
        let raw_array: &[u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid key length, expected 32 bytes"))?;
        let enc_sk = EncryptionPrivateKey::parse(raw_array).map_err(|e| anyhow!(" failed: {e}"))?;
        Ok(enc_sk)
    }

    async fn _get_persistent_secret_key(&self) -> Result<SigningPrivateKey> {
        dotenv().ok();
        let sk_hex = std::env::var("DIRTY_KMS_HEX")?;
        let raw: Vec<u8> = hex::decode(sk_hex)?;
        Ok(SigningPrivateKey::from_slice(&raw)?)
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
}

#[cfg(test)]
mod tests {
    use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
    use anyhow::Result;

    use crate::kms::kms::{DirtyKMS, KMS};

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
