use base58::ToBase58;
use hmac::Hmac;
use hmac::Mac;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ruint::aliases::U256;
use ruint::uint;
use sha2::Digest;
use sha2::Sha512;
use sha3::Keccak256;

/// Derives a 64-byte seed for an enclave using an image id.
/// The derivation is performed twice for additional security around length extension.
///
/// # Arguments
/// * `root` - A 64-byte root seed
/// * `image_id` - A 32-byte image id
///
/// # Examples
/// ```
/// use kms_derive_utils::derive_enclave_seed;
///
/// let root = [0u8; 64];
/// let image_id = [1u8; 32];
/// let seed = derive_enclave_seed(root, image_id);
/// ```
pub fn derive_enclave_seed(root: [u8; 64], image_id: [u8; 32]) -> [u8; 64] {
    derive_enclave_seed_once(derive_enclave_seed_once(root, image_id), image_id)
}

/// Derives a 64-byte seed for an enclave given a chain id and an address.
/// The derivation is performed twice for additional security around length extension.
///
/// # Arguments
/// * `root` - A 64-byte root seed
/// * `chain_id` - Chain ID
/// * `address` - Address (e.g. Ethereum or Solana)
///
/// # Examples
/// ```
/// use kms_derive_utils::derive_enclave_contract_seed;
///
/// let root = [0u8; 64];
/// let chain_id = 1;
/// let address = "0xffffffffffffffffffffffffffffffffffffffff";
/// let seed = derive_enclave_contract_seed(root, chain_id, address);
/// ```
pub fn derive_enclave_contract_seed(root: [u8; 64], chain_id: u64, address: &str) -> [u8; 64] {
    // normalize
    let address = &address.to_lowercase();
    derive_enclave_contract_seed_once(
        derive_enclave_contract_seed_once(root, chain_id, address),
        chain_id,
        address,
    )
}

/// Derives a 64-byte seed for a given path using a root seed.
/// The derivation is performed twice for additional security around length extension.
///
/// # Arguments
/// * `root` - A 64-byte root seed
/// * `path` - Path bytes to derive from
///
/// # Examples
/// ```
/// use kms_derive_utils::derive_path_seed;
///
/// let root = [0u8; 64];
/// let path = b"something";
/// let seed = derive_path_seed(root, path);
/// ```
pub fn derive_path_seed(root: [u8; 64], path: &[u8]) -> [u8; 64] {
    derive_path_seed_once(derive_path_seed_once(root, path), path)
}

/// Converts a 64-byte derived seed into a 32-byte secp256k1 secret key.
/// The key is guaranteed to be in the valid range [1, n-1] where n is the curve order.
///
/// ENDIANNESS: Big endian
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_secp256k1_secret;
///
/// let derived = [0u8; 64];
/// let secret = to_secp256k1_secret(derived);
/// ```
pub fn to_secp256k1_secret(derived: [u8; 64]) -> [u8; 32] {
    // throw away last 32 bytes, assumes derived is random
    // unlikely to ever matter if derived is random, but bound it to [1, n-1]
    // not perfectly random to mod but too negligible to care

    // SAFETY: can always take exactly 32 bytes, safe to unwrap
    U256::from_be_bytes::<32>(derived[..32].try_into().unwrap())
        .reduce_mod(uint!(
            // secp256k1 n-1, we want this to be [0, n-2]
            0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140_U256
        ))
        .wrapping_add(U256::from(1))
        .to_be_bytes::<32>()
}

/// Derives a 64-byte uncompressed secp256k1 public key from a 64-byte seed.
///
/// ENDIANNESS: Big endian
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_secp256k1_public;
///
/// let derived = [0u8; 64];
/// let public = to_secp256k1_public(derived);
/// ```
pub fn to_secp256k1_public(derived: [u8; 64]) -> [u8; 64] {
    // SAFETY: secret is the right size, safe to unwrap
    let secret = SecretKey::from_slice(&to_secp256k1_secret(derived)).unwrap();
    secret.public_key().to_encoded_point(false).as_bytes()[1..]
        .try_into()
        //SAFETY: encoded bytes should be 65 size, we take from 1, safe to unwrap
        .unwrap()
}

/// Derives an Ethereum address from a 64-byte seed.
/// Returns the address as a hex string with "0x" prefix.
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_secp256k1_ethereum_address;
///
/// let derived = [0u8; 64];
/// let address = to_secp256k1_ethereum_address(derived);
/// ```
pub fn to_secp256k1_ethereum_address(derived: [u8; 64]) -> String {
    let public = to_secp256k1_public(derived);
    let address = &Keccak256::new_with_prefix(&public).finalize()[12..];

    format!("0x{}", hex::encode(address))
}

/// Converts a 64-byte derived seed into a 32-byte Ed25519 secret key.
///
/// ENDIANNESS: Technically what is returned is a seed without endianness.
/// Libraries hash and clamp it to derive a secret, popular libraries use little endian.
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_ed25519_secret;
///
/// let derived = [0u8; 64];
/// let secret = to_ed25519_secret(derived);
/// ```
pub fn to_ed25519_secret(derived: [u8; 64]) -> [u8; 32] {
    // throw away last 32 bytes, assumes derived is random
    // SAFETY: can always take exactly 32 bytes, safe to unwrap
    derived[0..32].try_into().unwrap()
}

/// Derives a 32-byte Ed25519 public key from a 64-byte seed.
///
/// ENDIANNESS: Little endian
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_ed25519_public;
///
/// let derived = [0u8; 64];
/// let public = to_ed25519_public(derived);
/// ```
pub fn to_ed25519_public(derived: [u8; 64]) -> [u8; 32] {
    let secret = ed25519_dalek::SigningKey::from(to_ed25519_secret(derived));
    secret.verifying_key().to_bytes()
}

/// Derives a Solana address from a 64-byte seed.
/// Returns the address as a base58 encoded string.
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_ed25519_solana_address;
///
/// let derived = [0u8; 64];
/// let address = to_ed25519_solana_address(derived);
/// ```
pub fn to_ed25519_solana_address(derived: [u8; 64]) -> String {
    let public = to_ed25519_public(derived);

    public.to_base58()
}

/// Converts a 64-byte derived seed into a 32-byte X25519 secret key.
/// Applies proper clamping to ensure the key meets X25519 requirements.
///
/// ENDIANNESS: Little endian
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_x25519_secret;
///
/// let derived = [0u8; 64];
/// let secret = to_x25519_secret(derived);
/// ```
pub fn to_x25519_secret(derived: [u8; 64]) -> [u8; 32] {
    // throw away last 32 bytes, assumes derived is random
    // SAFETY: can always take exactly 32 bytes, safe to unwrap
    let mut secret: [u8; 32] = derived[0..32].try_into().unwrap();

    // most libraries do clamping internally, do it here just to be safe
    secret[0] &= 0b11111000; // unset last 3 bits
    secret[31] &= 0b01111111; // clear first bit
    secret[31] |= 0b01000000; // set second bit

    secret
}

/// Derives a 32-byte X25519 public key from a 64-byte seed.
///
/// ENDIANNESS: Little endian
///
/// # Arguments
/// * `derived` - A 64-byte derived seed
///
/// # Examples
/// ```
/// use kms_derive_utils::to_x25519_public;
///
/// let derived = [0u8; 64];
/// let public = to_x25519_public(derived);
/// ```
pub fn to_x25519_public(derived: [u8; 64]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(to_x25519_secret(derived));
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn derive_enclave_seed_once(root: [u8; 64], image_id: [u8; 32]) -> [u8; 64] {
    // SAFETY: cannot error, safe to unwrap
    let mut mac = Hmac::<Sha512>::new_from_slice(&root).unwrap();
    mac.update(&image_id);

    mac.finalize().into_bytes().into()
}

fn derive_enclave_contract_seed_once(root: [u8; 64], chain_id: u64, address: &str) -> [u8; 64] {
    // SAFETY: cannot error, safe to unwrap
    let mut mac = Hmac::<Sha512>::new_from_slice(&root).unwrap();
    mac.update(&chain_id.to_le_bytes());
    mac.update(&address.as_bytes());

    mac.finalize().into_bytes().into()
}

fn derive_path_seed_once(root: [u8; 64], path: &[u8]) -> [u8; 64] {
    // SAFETY: cannot error, safe to unwrap
    let mut mac = Hmac::<Sha512>::new_from_slice(&root).unwrap();
    mac.update(&path);

    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{
        derive_enclave_contract_seed, derive_enclave_seed, derive_path_seed, to_ed25519_public,
        to_ed25519_secret, to_ed25519_solana_address, to_secp256k1_ethereum_address,
        to_secp256k1_public, to_secp256k1_secret, to_x25519_public, to_x25519_secret,
    };

    #[test]
    fn test_derive_enclave_seed() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let image_id = hex!("107a6d53ba665ae961bb407bccf8b8bc95fa048e1eb59e012caac30ef29d72a9");
        // derived from an independent online implementation
        let expected = hex!("b63552edbd62d2c95b3c8662934d6c0d1cb9dab6177ca59a6d228d586e5257a95a21725f3ca3cfb9b1f9816fd10ce6d877048b1f3d7e1496abee9d8afc7f54ce");

        let seed = derive_enclave_seed(root, image_id);

        assert_eq!(seed, expected);
    }

    #[test]
    fn test_derive_enclave_seed_eth() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let chain_id = 0x1234;
        let address = "0x92148e8F84096d0Dfe7E66a025d14D1e2594DDc2";
        // derived from an independent online implementation
        let expected = hex!("2893103cf566e7d2df9da1aec5e6c3f66a1d03e4031d6cd22282bab6415fc4da8a16b299c1e570115f0ec4173fa1f192e22dea29e21c2328ace3773151eacdcb");

        let seed = derive_enclave_contract_seed(root, chain_id, address);

        assert_eq!(seed, expected);
    }

    #[test]
    fn test_derive_enclave_seed_sol() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let chain_id = 0x5678;
        let address = "BEYzkmcGNdhqHAPKQ7oz89n1RbAumm2kwtX113pPuCax";
        // derived from an independent online implementation
        let expected = hex!("ac30d6400265019af7c7bca9386021ad9299c2094bc8ebdeef8f0143afd2740ae8d119478b336e7509e7d7cf2a9d6e9f8ffbb03aa78c4e3f59e9141e063f1421");

        let seed = derive_enclave_contract_seed(root, chain_id, address);

        assert_eq!(seed, expected);
    }

    #[test]
    fn test_derive_path_seed() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let path = hex!("0336b1a0838f0bd3");
        // derived from an independent online implementation
        let expected = hex!("77dd95c3ad1c4aec2370d79ad1cbab5399b0f893e203653c3a60a9a63f0c6f6d309cecab1007c4a893bc5e23180d5de25038420d70c309446c99581844f93fa0");

        let seed = derive_path_seed(root, &path);

        assert_eq!(seed, expected);
    }

    #[test]
    fn test_to_secp256k1_secret() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let expected = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf3");

        let secret = to_secp256k1_secret(derived);

        assert_eq!(secret, expected);
    }

    #[test]
    fn test_to_secp256k1_secret_max() {
        let derived = hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let expected = hex!("000000000000000000000000000000014551231950b75fc4402da1732fc9bec0");

        let secret = to_secp256k1_secret(derived);

        assert_eq!(secret, expected);
    }

    #[test]
    fn test_to_secp256k1_secret_zero() {
        let derived = hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let expected = hex!("0000000000000000000000000000000000000000000000000000000000000001");

        let secret = to_secp256k1_secret(derived);

        assert_eq!(secret, expected);
    }

    #[test]
    fn test_to_secp256k1_public() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        // derived from an independent online implementation
        let expected = hex!("19123e8d4b151f2b6b5f25a6d22b50a29522bc828b64c0764cf8e743dffe87d64af1c7457e17dffa208f986b347340295ecb8433d47d3b2221f81a619cef0a0b");

        let public = to_secp256k1_public(derived);

        assert_eq!(public, expected);
    }

    #[test]
    fn test_to_secp256k1_ethereum_address() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        // derived from an independent online implementation
        let expected = "0x92148e8f84096d0dfe7e66a025d14d1e2594ddc2";

        let address = to_secp256k1_ethereum_address(derived);

        assert_eq!(address, expected);
    }

    #[test]
    fn test_to_ed25519_secret() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let expected = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2");

        let secret = to_ed25519_secret(derived);

        assert_eq!(secret, expected);
    }

    #[test]
    fn test_to_ed25519_public() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        // derived from an independent online implementation
        let expected = hex!("980d98f6a6629647c840311b9d55e8808a75e16fd04468c115de3c4dbd6c249d");

        let public = to_ed25519_public(derived);

        assert_eq!(public, expected);
    }

    #[test]
    fn test_to_ed25519_solana_address() {
        let derived = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        // derived from an independent online implementation
        let expected = "BEYzkmcGNdhqHAPKQ7oz89n1RbAumm2kwtX113pPuCax";

        let address = to_ed25519_solana_address(derived);

        assert_eq!(address, expected);
    }

    #[test]
    fn test_to_x25519_secret() {
        let derived = hex!("4790382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdb2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let expected = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cd72");

        let secret = to_x25519_secret(derived);

        assert_eq!(secret, expected);
    }

    #[test]
    fn test_to_x25519_public() {
        let derived = hex!("4790382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdb2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        // derived from an independent online implementation
        let expected = hex!("7e80b46b5f95e629ef1b24b42d3af5dc4e6dd50046376d316956573db2e7d623");

        let public = to_x25519_public(derived);

        assert_eq!(public, expected);
    }
}
