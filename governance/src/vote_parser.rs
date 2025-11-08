use alloy::network::{Ethereum, Network};
use alloy::primitives::{B256, U256};
use anyhow::{Result, anyhow};
use ecies::SecretKey as EncryptionPrivateKey;
use std::sync::{Arc, Mutex};

use crate::delegation::Delegation;
use crate::token::TokenInstance;
use crate::vote_factory::WeightVoteDecision;
use crate::{
    governance::{Governance, IGovernance::ProposalTimeInfo},
    vote_factory::VoteFactory,
};

use crate::config::{find_block_by_timestamp, get_config, get_governance_enclave};

pub struct VoteParse<N: Network> {
    governance: Governance<N>,
}

impl<N: Network> VoteParse<N> {
    pub fn new(governance: Governance<N>) -> Self {
        Self { governance }
    }

    pub async fn get_proposal_timing_info(&self, proposal_id: B256) -> Result<ProposalTimeInfo> {
        let info = self
            .governance
            .get_proposal_timing_info(proposal_id)
            .await?;
        Ok(info)
    }

    pub async fn parse_votes(
        &self,
        proposal_id: B256,
        vote_factory: Arc<Mutex<VoteFactory>>,
        sk: EncryptionPrivateKey,
    ) -> Result<()> {
        // 1) Read total votes
        let mut vf = vote_factory
            .lock()
            .map_err(|e| anyhow!("unable to get lock (mutex poisoned): {e}"))?;
        if vf.is_complete() {
            drop(vf); // manually dropping for safety
            return Ok(());
        }

        let vote_count_u256: U256 = self.governance.get_vote_count(proposal_id).await?;

        // Convert U256 -> u64 (fail loudly if it doesn't fit)
        let total: u64 = vote_count_u256
            .try_into()
            .map_err(|_| anyhow!("vote_count does not fit into u64"))?;

        for i in 0..total {
            let index_u256 = U256::from(i);

            let vote = self
                .governance
                .get_single_vote(proposal_id, index_u256)
                .await?;

            let decision = vote.to_vote_decision(sk.clone(), proposal_id);

            vf.set_vote(index_u256, decision);
        }

        drop(vf);

        self.parse_votes_weight(vote_factory.clone()).await?;

        Ok(())
    }

    async fn parse_votes_weight(&self, vote_factory: Arc<Mutex<VoteFactory>>) -> Result<()> {
        // --- 1) Snapshot from vf, then drop the lock ---
        let (votes_by_chain, proposal_ts) = {
            let vf = vote_factory
                .lock()
                .map_err(|e| anyhow!("unable to get lock (mutex poisoned): {e}"))?;

            if vf.is_complete() {
                return Ok(());
            }

            // Clone the map so we can drop the guard before any await
            let votes_by_chain = vf.votes_by_chain_id().clone();
            let proposal_ts: u64 = vf.proposal_create_timestamp().to::<u64>();
            (votes_by_chain, proposal_ts)
            // vf guard is dropped here
        };

        // --- 2) Do async work without holding the lock ---
        let cfg = get_config()?;
        let governance_enclave = get_governance_enclave::<Ethereum>()?;

        let mut updates: Vec<WeightVoteDecision> = Vec::new();

        for (chain_id, address_vote_map) in votes_by_chain {
            let chain_key = chain_id.to_string();

            let rpc_url: &str = cfg
                .other_rpc_urls
                .get(&chain_key)
                .map(|s| s.as_str())
                .ok_or_else(|| {
                    anyhow!("missing RPC URL for chain {chain_key} in other_rpc_urls")
                })?;

            let nearest_block_to_proposal_creation =
                find_block_by_timestamp::<Ethereum>(rpc_url, proposal_ts).await?;

            let delegation_contract_address = self
                .governance
                .get_delegation_contract_address(chain_id.clone())
                .await?;

            let delegation = Delegation::<Ethereum>::new(
                rpc_url,
                delegation_contract_address.to_string().as_ref(),
            )?;

            let token_network_config = governance_enclave
                .get_token_network_config(chain_id.clone())
                .await?;

            let token_instance = TokenInstance::<Ethereum>::new(
                rpc_url,
                token_network_config.tokenAddress.to_string().as_ref(),
            )?;

            for (delegator_or_voter, decision) in address_vote_map {
                if let Some(_dgtr) = decision.get_delegator_address() {
                    let delegatee_as_per_contract = delegation
                        .get_delegatee(_dgtr.clone(), nearest_block_to_proposal_creation)
                        .await?;

                    if delegatee_as_per_contract != decision.get_voter_address() {
                        continue;
                    }
                }

                // if delegatee is not set, then
                let token_weight = token_instance
                    .get_token_weight(
                        delegator_or_voter.clone(),
                        nearest_block_to_proposal_creation,
                    )
                    .await?;

                updates.push(WeightVoteDecision {
                    decision: decision.clone(),
                    weight: token_weight,
                });

                // other cases, should be invalid votes
            }
        }

        // --- 3) Re-lock to mutate vf and mark complete ---
        {
            let mut vf = vote_factory
                .lock()
                .map_err(|e| anyhow!("unable to get lock (mutex poisoned): {e}"))?;
            for w in updates {
                vf.set_vote_weight(w)?;
            }
            vf.set_complete(true);
        }

        Ok(())
    }
}
