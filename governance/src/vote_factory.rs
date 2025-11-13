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

/// A vote decision bundled with its token-based voting weight.
///
/// This represents a single interpreted vote plus the amount of voting
/// power attached to it at a specific block:
///
/// - `decision` – the high-level [`VoteDecision`] (Yes/No/etc.).
/// - `weight` – the [`TokenWeight`] resolved from the underlying token
///   contract on the relevant chain.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeightVoteDecision {
    pub decision: VoteDecision,
    pub weight: TokenWeight,
}

/// In-memory store for raw, deduplicated, and weighted votes for a proposal.
///
/// `VoteFactory` is responsible for:
/// - tracking all votes by on-chain index,
/// - deduplicating valid votes per `(chain_id, address)` pair,
/// - storing weighted votes after token lookups,
/// - exposing metadata like proposal timing and an aggregate vote hash,
/// - and carrying a `complete` flag to signal when processing is finished.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteFactory {
    vote_by_index: HashMap<U256, VoteDecision>,
    unique_valid_votes: HashMap<U256, HashMap<Address, VoteDecision>>,
    proposal_time_info: ProposalTimeInfo,
    unique_valid_weighted_votes: HashMap<U256, HashMap<Address, WeightVoteDecision>>,
    complete: bool,
}

impl VoteFactory {
    /// Creates a new [`VoteFactory`] for a given proposal.
    ///
    /// - `proposal_time_info` – timing data fetched from the governance contract
    ///   (used, for example, to derive the proposal creation timestamp).
    ///
    /// The factory starts empty and `complete` is initialized to `false`.
    pub fn new(proposal_time_info: ProposalTimeInfo) -> Self {
        Self {
            vote_by_index: HashMap::default(),
            unique_valid_votes: HashMap::default(),
            unique_valid_weighted_votes: HashMap::default(),
            proposal_time_info,
            complete: false,
        }
    }

    /// Returns the proposal creation timestamp as reported on-chain.
    ///
    /// This is taken directly from `proposal_time_info.proposedTimestamp`
    /// and is typically used to locate the block nearest to proposal creation.
    pub fn proposal_create_timestamp(&self) -> U256 {
        self.proposal_time_info.proposedTimestamp
    }

    /// Returns the interpreted vote at the given on-chain index, if present.
    ///
    /// This uses the flat `vote_by_index` map and does not perform any
    /// deduplication or weighting logic.
    pub fn get_vote(&self, idx: &U256) -> Option<&VoteDecision> {
        self.vote_by_index.get(idx)
    }
    /// Inserts or updates a vote at a given on-chain index and updates deduplicated maps.
    ///
    /// Behavior:
    /// - Always stores `decision` in `vote_by_index` under `idx`.
    /// - If the decision carries a `chain_id` (via [`VoteDecision::get_chain_id`]),
    ///   it is also inserted into `unique_valid_votes[chain_id][address]`, where
    ///   `address` is either:
    ///   - the delegator address (if present), or
    ///   - the voter address as a fallback.
    ///
    /// Returns the previous vote stored at `idx`, if there was one.
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

    /// Records a weighted vote into the deduplicated weighted map.
    ///
    /// If the wrapped [`VoteDecision`] has a `chain_id`, this method:
    /// - computes the relevant address (delegator if set, otherwise voter),
    /// - inserts or updates the entry in
    ///   `unique_valid_weighted_votes[chain_id][address]` with the provided
    ///   [`WeightVoteDecision`].
    ///
    /// Returns `Ok(())` on success. Votes without a `chain_id` are ignored for
    /// the weighted map (but may still exist in the unweighted store).
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

    /// Removes and returns the vote stored at the given on-chain index, if any.
    ///
    /// This only affects the flat `vote_by_index` map and does **not** update
    /// the deduplicated maps. Use with care if you rely on strict consistency
    /// between the different views.
    pub fn remove_vote(&mut self, idx: &U256) -> Option<VoteDecision> {
        self.vote_by_index.remove(idx)
    }

    /// Removes and returns the vote stored at the given on-chain index, if any.
    ///
    /// This only affects the flat `vote_by_index` map and does **not** update
    /// the deduplicated maps. Use with care if you rely on strict consistency
    /// between the different views.
    pub fn has_vote(&self, idx: &U256) -> bool {
        self.vote_by_index.contains_key(idx)
    }

    /// Removes and returns the vote stored at the given on-chain index, if any.
    ///
    /// This only affects the flat `vote_by_index` map and does **not** update
    /// the deduplicated maps. Use with care if you rely on strict consistency
    /// between the different views.
    pub fn votes(&self) -> &HashMap<U256, VoteDecision> {
        &self.vote_by_index
    }

    /// Returns a mutable view of all votes keyed by on-chain index.
    ///
    /// Direct mutation through this map bypasses deduplication logic; prefer
    /// [`Self::set_vote`] when possible to keep derived maps in sync.
    pub fn votes_mut(&mut self) -> &mut HashMap<U256, VoteDecision> {
        &mut self.vote_by_index
    }

    /// Returns deduplicated valid votes grouped by chain ID and address.
    ///
    /// The structure is:
    /// - outer key: `chain_id` (`U256`),
    /// - inner key: voter or delegator [`Address`] (see [`Self::set_vote`]),
    /// - value: the associated [`VoteDecision`].
    ///
    /// Only decisions that expose a `chain_id` are included here.
    pub fn votes_by_chain_id(&self) -> &HashMap<U256, HashMap<Address, VoteDecision>> {
        &self.unique_valid_votes
    }

    /// Returns deduplicated weighted votes grouped by chain ID and address.
    ///
    /// This map mirrors [`Self::votes_by_chain_id`] but stores
    /// [`WeightVoteDecision`] values, after token-based weights have been
    /// computed and applied.
    pub fn weighted_votes(&self) -> &HashMap<U256, HashMap<Address, WeightVoteDecision>> {
        &self.unique_valid_weighted_votes
    }

    /// Returns a mutable view of deduplicated valid votes grouped by chain ID.
    ///
    /// Direct mutation here may desynchronize state from `vote_by_index` or
    /// `unique_valid_weighted_votes`; prefer using [`Self::set_vote`] and
    /// [`Self::set_vote_weight`] for normal updates.
    pub fn votes_mut_by_chain_id(&mut self) -> &mut HashMap<U256, HashMap<Address, VoteDecision>> {
        &mut self.unique_valid_votes
    }

    /// Returns a mutable view of deduplicated valid votes grouped by chain ID.
    ///
    /// Direct mutation here may desynchronize state from `vote_by_index` or
    /// `unique_valid_weighted_votes`; prefer using [`Self::set_vote`] and
    /// [`Self::set_vote_weight`] for normal updates.
    pub fn len(&self) -> usize {
        self.vote_by_index.len()
    }

    /// Computes a deterministic hash over all stored on-chain votes.
    ///
    /// For each vote in `vote_by_index`:
    /// - hashes the `voteEncrypted` payload,
    /// - ABI-encodes `(voter, delegator, delegatorChainId, voteEncryptedHash)`
    ///   into a `CurrentVoteHashInput` and hashes it,
    /// - folds it into the running accumulator using a `FinalizeVoteHashInput`
    ///   struct and `sha256`.
    ///
    /// The final accumulator is returned as a [`B256`] and is intended to match
    /// the on-chain vote hash (or be comparable to it) given the same inputs.
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

    /// Returns `true` if no votes have been recorded in `vote_by_index`.
    pub fn is_empty(&self) -> bool {
        self.vote_by_index.is_empty()
    }

    /// Returns `true` if no votes have been recorded in `vote_by_index`.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns `true` if no votes have been recorded in `vote_by_index`.
    pub fn set_complete(&mut self, value: bool) {
        self.complete = value;
    }
}
