use std::time::{SystemTime, UNIX_EPOCH};

use alloy::signers::k256::sha2::{Digest, Sha256};
use oyster::{
    attestation::{self, AttestationExpectations, AWS_ROOT_KEY},
    scallop::{Key, ScallopAuthStore},
};

#[derive(Clone, Default)]
pub struct AuthStore {}

// holds image id
pub type AuthStoreState = [u8; 32];

impl ScallopAuthStore for AuthStore {
    type State = AuthStoreState;

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State> {
        let Ok(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_millis() as usize)
        else {
            return None;
        };

        let Ok(decoded) = attestation::verify(
            attestation,
            AttestationExpectations {
                // TODO: hardcoded, make it a param
                age: Some((300000, now)),
                root_public_key: Some(&AWS_ROOT_KEY),
                public_key: Some(&key),
                // do not care about PCRs or user data
                // will derive different keys for each set
                ..Default::default()
            },
        ) else {
            return None;
        };

        if decoded.user_data.len() > 65535 {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(hex::decode(decoded.pcrs[0]).unwrap());
        hasher.update(hex::decode(decoded.pcrs[1]).unwrap());
        hasher.update(hex::decode(decoded.pcrs[2]).unwrap());
        hasher.update((decoded.user_data.len() as u16).to_be_bytes());
        hasher.update(decoded.user_data);
        let image_id = hasher.finalize().into();

        return Some(image_id);
    }
}
