use std::{
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use oyster::{
    attestation::{self, AttestationExpectations, AWS_ROOT_KEY},
    scallop::{Key, ScallopAuthStore, ScallopAuther},
};

#[derive(Clone)]
pub struct AuthStore {
    pub state: ([[u8; 48]; 3], Box<[u8]>),
}

impl ScallopAuthStore for AuthStore {
    type State = ();

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State> {
        let Ok(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_millis() as usize)
        else {
            return None;
        };

        let Ok(_) = attestation::verify(
            attestation,
            AttestationExpectations {
                // TODO: hardcoded, make it a param
                age: Some((300000, now)),
                root_public_key: Some(&AWS_ROOT_KEY),
                pcrs: Some(self.state.0),
                user_data: Some(&self.state.1),
                public_key: Some(&key),
                ..Default::default()
            },
        ) else {
            return None;
        };

        return Some(());
    }
}

#[derive(Clone)]
pub struct Auther {
    pub url: String,
}

impl ScallopAuther for Auther {
    type Error = anyhow::Error;

    async fn new_auth(&mut self) -> Result<Box<[u8]>> {
        let body = reqwest::get(&self.url)
            .await
            .context("failed to fetch attestation")?
            .bytes()
            .await
            .context("failed to read attestation")?;
        Ok(body.deref().into())
    }
}
