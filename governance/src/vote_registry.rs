use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::U256;
use alloy::primitives::{B256, map::HashMap};
use serde::{Deserialize, Serialize};

use crate::vote_factory::VoteFactory;
use crate::{governance::IGovernance::ProposalTimeInfo, proposal::VoteDecision};
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VoteRegistry {
    factory_by_proposal_id: RwLock<HashMap<B256, Arc<Mutex<VoteFactory>>>>,
}

impl Clone for VoteRegistry {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl VoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_factory(
        &self,
        proposal_id: B256,
        proposal_time_info: ProposalTimeInfo,
    ) -> Result<Arc<Mutex<VoteFactory>>> {
        let mut write = self
            .factory_by_proposal_id
            .write()
            .map_err(|e| anyhow!("rwlock poisoned on write: {e}"))?;

        if write.contains_key(&proposal_id) {
            anyhow::bail!("VoteFactory already exists for proposal_id {proposal_id:?}");
        }

        let vf = Arc::new(Mutex::new(VoteFactory::new(proposal_time_info)));
        write.insert(proposal_id, vf.clone());
        Ok(vf)
    }

    /// Get the existing VoteFactory for `proposal_id`, if any.
    pub fn get_factory(&self, proposal_id: &B256) -> Result<Option<Arc<Mutex<VoteFactory>>>> {
        let read = self
            .factory_by_proposal_id
            .read()
            .map_err(|e| anyhow!("rwlock poisoned on read: {e}"))?;
        Ok(read.get(proposal_id).cloned())
    }

    /// Set/replace the vote for an address under a proposal.
    pub fn set_vote(&self, proposal_id: B256, idx: U256, decision: VoteDecision) -> Result<()> {
        let Some(factory) = self.get_factory(&proposal_id)? else {
            anyhow::bail!("no VoteFactory for proposal_id {proposal_id:?}");
        };
        let mut guard = factory
            .lock()
            .map_err(|e| anyhow!("mutex poisoned for VoteFactory: {e}"))?;
        guard.set_vote(idx, decision);
        Ok(())
    }

    /// Get a vote (if any) for an address under a proposal.
    pub fn get_vote(&self, proposal_id: B256, idx: &U256) -> Result<Option<VoteDecision>> {
        let map_read = self
            .factory_by_proposal_id
            .read()
            .map_err(|e| anyhow!("rwlock poisoned on read: {e}"))?;

        let factory = match map_read.get(&proposal_id) {
            Some(f) => f.clone(),
            None => return Ok(None),
        };
        drop(map_read); // release map lock ASAP

        let guard = factory
            .lock()
            .map_err(|e| anyhow!("mutex poisoned for VoteFactory: {e}"))?;
        Ok(guard.get_vote(idx).cloned())
    }

    /// Remove a vote for an address under a proposal.
    pub fn remove_vote(&self, proposal_id: B256, idx: &U256) -> Result<Option<VoteDecision>> {
        let Some(factory) = self.get_factory(&proposal_id)? else {
            return Ok(None);
        };
        let mut guard = factory
            .lock()
            .map_err(|e| anyhow!("mutex poisoned for VoteFactory: {e}"))?;
        Ok(guard.remove_vote(idx))
    }

    /// Does this proposal exist?
    pub fn has_proposal(&self, proposal_id: &B256) -> Result<bool> {
        let read = self
            .factory_by_proposal_id
            .read()
            .map_err(|e| anyhow!("rwlock poisoned on read: {e}"))?;
        Ok(read.contains_key(proposal_id))
    }

    /// Number of proposals being tracked.
    pub fn proposals_len(&self) -> Result<usize> {
        let read = self
            .factory_by_proposal_id
            .read()
            .map_err(|e| anyhow!("rwlock poisoned on read: {e}"))?;
        Ok(read.len())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config,
        governance::Governance,
        governance_enclave::GovernanceEnclave,
        kms::kms::{DirtyKMS, KMS},
        vote_parser::VoteParse,
        vote_registry::VoteRegistry,
    };
    use alloy::network::Ethereum;
    use anyhow::Result;
    use dotenvy::dotenv;

    #[tokio::test]
    async fn read_info() -> Result<()> {
        dotenv().ok();
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        let sk: ecies::SecretKey = DirtyKMS::default()
            .get_proposal_secret_key(proposal_id.parse()?)
            .await?;

        let governance: Governance<Ethereum> = config::get_governance()?;
        let governance_enclave: GovernanceEnclave<Ethereum> = config::get_governance_enclave()?;

        let proposal_time_info = governance
            .get_proposal_timing_info(proposal_id.parse()?)
            .await?;

        let vote_parser = VoteParse::new(governance, governance_enclave);

        let vote_registry = VoteRegistry::new();
        let vote_factory =
            vote_registry.create_factory(proposal_id.parse()?, proposal_time_info)?;
        vote_parser
            .parse_votes(proposal_id.parse()?, vote_factory, sk)
            .await?;

        println!("{}", "vote_registry");
        println!("{:?}", vote_registry);

        Ok(())
    }
}
