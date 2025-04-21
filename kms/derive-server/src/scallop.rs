use std::ops::Deref;

use anyhow::{Context, Result};
use oyster::scallop::{Key, ScallopAuthStore, ScallopAuther};

#[derive(Clone)]
pub struct AuthStore {
    pub pubkey: Key,
}

impl ScallopAuthStore for AuthStore {
    type State = ();

    // directly compare against the expected key for an early approve/reject
    fn contains(&mut self, key: &Key) -> oyster::scallop::ContainsResponse<Self::State> {
        use oyster::scallop::ContainsResponse::*;
        if key == &self.pubkey {
            Approved(())
        } else {
            Rejected
        }
    }

    // should never be called since we never return NotFound above
    fn verify(&mut self, _attestation: &[u8], _key: Key) -> Option<Self::State> {
        unimplemented!()
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
