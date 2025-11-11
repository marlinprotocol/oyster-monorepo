use alloy::{
    primitives::{Address, B256, U256},
    signers::k256::sha2::{Digest, Sha256},
    sol,
    sol_types::SolValue,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    governance::IGovernance::ProposalTimeInfo, proposal::VoteDecision, token::TokenWeight,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeightVoteDecision {
    pub decision: VoteDecision,
    pub weight: TokenWeight,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteFactory {
    vote_by_index: HashMap<U256, VoteDecision>,
    unique_valid_votes: HashMap<U256, HashMap<Address, VoteDecision>>,
    proposal_time_info: ProposalTimeInfo,
    unique_valid_weighted_votes: HashMap<U256, HashMap<Address, WeightVoteDecision>>,
    complete: bool,
}

impl VoteFactory {
    pub fn new(proposal_time_info: ProposalTimeInfo) -> Self {
        Self {
            vote_by_index: HashMap::default(),
            unique_valid_votes: HashMap::default(),
            unique_valid_weighted_votes: HashMap::default(),
            proposal_time_info,
            complete: false,
        }
    }

    pub fn proposal_create_timestamp(&self) -> U256 {
        self.proposal_time_info.proposedTimestamp
    }

    pub fn get_vote(&self, idx: &U256) -> Option<&VoteDecision> {
        self.vote_by_index.get(idx)
    }

    pub fn set_vote(&mut self, idx: U256, decision: VoteDecision) -> Option<VoteDecision> {
        // If the decision carries a chain id, index it by (chain_id, address)
        if let Some(chain_id) = decision.get_chain_id() {
            let addr = decision
                .get_delegator_address()
                .unwrap_or(decision.get_voter_address());

            // Ensure inner map exists for this chain_id, then upsert by address
            self.unique_valid_votes
                .entry(chain_id)
                .or_default()
                .insert(addr, decision.clone());
        }

        // Always keep the flat index by vote index
        self.vote_by_index.insert(idx, decision)
    }

    pub fn set_vote_weight(&mut self, weighted_vote_decision: WeightVoteDecision) -> Result<()> {
        if let Some(chain_id) = weighted_vote_decision.decision.get_chain_id() {
            let addr = weighted_vote_decision
                .decision
                .get_delegator_address()
                .unwrap_or(weighted_vote_decision.decision.get_voter_address());

            // Ensure inner map exists for this chain_id, then upsert by address
            self.unique_valid_weighted_votes
                .entry(chain_id)
                .or_default()
                .insert(addr, weighted_vote_decision.clone());
        }

        Ok(())
    }

    pub fn remove_vote(&mut self, idx: &U256) -> Option<VoteDecision> {
        self.vote_by_index.remove(idx)
    }

    pub fn has_vote(&self, idx: &U256) -> bool {
        self.vote_by_index.contains_key(idx)
    }

    pub fn votes(&self) -> &HashMap<U256, VoteDecision> {
        &self.vote_by_index
    }

    pub fn votes_mut(&mut self) -> &mut HashMap<U256, VoteDecision> {
        &mut self.vote_by_index
    }

    pub fn votes_by_chain_id(&self) -> &HashMap<U256, HashMap<Address, VoteDecision>> {
        &self.unique_valid_votes
    }

    pub fn weighted_votes(&self) -> &HashMap<U256, HashMap<Address, WeightVoteDecision>> {
        &self.unique_valid_weighted_votes
    }

    pub fn votes_mut_by_chain_id(&mut self) -> &mut HashMap<U256, HashMap<Address, VoteDecision>> {
        &mut self.unique_valid_votes
    }

    pub fn len(&self) -> usize {
        self.vote_by_index.len()
    }

    pub fn vote_hash(&self) -> B256 {
        let mut init_vote_hash = B256::ZERO;
        for (_, vote_decision) in self.vote_by_index.iter() {
            let on_chain_vote = vote_decision.get_on_chain_vote();
            let vote_encrypted_hash: B256 = {
                let h = Sha256::digest(on_chain_vote.voteEncrypted.clone()); // returns generic-array [u8; 32]
                B256::from_slice(&h)
            };

            sol! {
                struct CurrentVoteHashInput {
                    address voter;
                    address delegator;
                    uint256 chainId;
                    bytes32 voteEncryptedHash;
                }
            }

            let cvhi = CurrentVoteHashInput {
                voter: on_chain_vote.voter,
                delegator: on_chain_vote.delegator,
                chainId: on_chain_vote.delegatorChainId,
                voteEncryptedHash: vote_encrypted_hash,
            };

            let current_vote_hash: B256 = {
                let h = Sha256::digest(cvhi.abi_encode()); // returns generic-array [u8; 32]
                B256::from_slice(&h)
            };

            sol! {
                struct FinalizeVoteHashINput {
                    bytes32 a;
                    bytes32 b;
                }
            }

            let fvhi = FinalizeVoteHashINput {
                a: init_vote_hash,
                b: current_vote_hash,
            };
            init_vote_hash = {
                let h = Sha256::digest(fvhi.abi_encode()); // returns generic-array [u8; 32]
                B256::from_slice(&h)
            };
        }

        init_vote_hash
    }

    pub fn is_empty(&self) -> bool {
        self.vote_by_index.is_empty()
    }

    // ---- complete flag ----
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn set_complete(&mut self, value: bool) {
        self.complete = value;
    }
}
