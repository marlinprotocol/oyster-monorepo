use anyhow::{Context, Result, anyhow, bail};
use ethers::types::H256;
use libsodium_sys::{
    crypto_box_SEALBYTES, crypto_box_seal_open, crypto_scalarmult_base, sodium_init,
};
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::types::VoteOutcome;

pub fn fetch_encryption_key(endpoint: &str) -> Result<[u8; 32]> {
    let url = format!("{}/derive/x25519", endpoint);

    ureq::get(&url)
        .query("path", "gov_key")
        .call()
        .context("failed to call derive server for encryption key")?
        .body_mut()
        .read_to_vec()
        .context("failed to read encryption key response body")?
        .as_slice()
        .try_into()
        .context("failed to parse encryption key response")
}

pub fn fetch_signing_key(endpoint: &str) -> Result<[u8; 32]> {
    let url = format!("{}/derive/secp256k1", endpoint);

    ureq::get(&url)
        .query("path", "gov_key")
        .call()
        .context("failed to call derive server for signing key")?
        .body_mut()
        .read_to_vec()
        .context("failed to read signing key response body")?
        .as_slice()
        .try_into()
        .context("failed to parse signing key response")
}

pub fn setup_libsodium() -> Result<()> {
    if unsafe { sodium_init() } < 0 {
        bail!("failed to init libsodium");
    }
    Ok(())
}

pub fn derive_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let mut public_key = [0u8; 32];
    unsafe { crypto_scalarmult_base(public_key.as_mut_ptr(), secret_key.as_ptr()) };
    public_key
}

pub fn sign_vote_result(hash: H256, privkey_array: [u8; 32]) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();

    let secret_key = SecretKey::from_byte_array(privkey_array)
        .map_err(|e| anyhow!("failed to create SecretKey: {}", e))?;

    let msg = Message::from_digest(hash.into());

    let sig = secp.sign_ecdsa_recoverable(msg, &secret_key);
    let (recovery_id, compact_sig) = sig.serialize_compact();

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&compact_sig[..]);
    sig_bytes[64] = (Into::<i32>::into(recovery_id) as u8) + 27;

    Ok(sig_bytes.to_vec())
}

pub fn decrypt_vote(encrypted: &[u8], pk: &[u8; 32], sk: &[u8; 32]) -> Result<VoteOutcome> {
    if encrypted.len() < crypto_box_SEALBYTES as usize {
        anyhow::bail!(
            "Encrypted vote too short: got {}, expected at least {}",
            encrypted.len(),
            crypto_box_SEALBYTES
        );
    }

    let mut decrypted = vec![0u8; encrypted.len() - crypto_box_SEALBYTES as usize];

    let status = unsafe {
        crypto_box_seal_open(
            decrypted.as_mut_ptr(),
            encrypted.as_ptr(),
            encrypted.len() as u64,
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };

    if status != 0 {
        anyhow::bail!("Failed to decrypt vote using enclave key");
    }

    let outcome_byte = *decrypted
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("Invalid decrypted vote"))?;

    VoteOutcome::try_from(outcome_byte)
}
