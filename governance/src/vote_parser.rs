use alloy::network::{Ethereum, Network};
use alloy::primitives::{Address, B256, U256};
use anyhow::{Result, anyhow};
use ecies::SecretKey as EncryptionPrivateKey;
use std::sync::{Arc, Mutex};

use crate::delegation::Delegation;
use crate::governance_enclave::GovernanceEnclave;
use crate::token::TokenInstance;
use crate::vote_factory::WeightVoteDecision;
use crate::{
    governance::{Governance, IGovernance::ProposalTimeInfo},
    vote_factory::VoteFactory,
};

use crate::config::{self, find_block_by_timestamp};

/// High-level helper for reading and interpreting votes for a proposal.
///
/// `VoteParse` ties together:
/// - [`Governance`] – to read on-chain proposal and vote data on the governance chain.
/// - [`GovernanceEnclave`] – to resolve token network configs and delegation contracts
///   on external chains.
///
/// It is responsible for:
/// - fetching raw votes from the governance contract,
/// - converting them into interpreted decisions,
/// - resolving delegation rules and token weights,
/// - and pushing the final weighted decisions into a shared [`VoteFactory`].
pub struct VoteParse<N: Network> {
    governance: Governance<N>,
    governance_enclave: GovernanceEnclave<N>,
}

impl<N: Network> VoteParse<N> {
    /// Creates a new [`VoteParse`] instance.
    ///
    /// - `governance` – client bound to the on-chain governance contract.
    /// - `governance_enclave` – client used to resolve token and delegation
    ///   configuration across chains.
    ///
    /// This does not perform any network I/O and is cheap to construct.
    pub fn new(governance: Governance<N>, governance_enclave: GovernanceEnclave<N>) -> Self {
        Self {
            governance,
            governance_enclave,
        }
    }

    /// Fetches timing information for a given proposal.
    ///
    /// This is a thin wrapper around [`Governance::get_proposal_timing_info`],
    /// returning the [`ProposalTimeInfo`] for `proposal_id`, which includes:
    /// - when the proposal was created,
    /// - when voting activates,
    /// - and when voting / proposal lifetimes end.
    pub async fn get_proposal_timing_info(&self, proposal_id: B256) -> Result<ProposalTimeInfo> {
        let info = self
            .governance
            .get_proposal_timing_info(proposal_id)
            .await?;
        Ok(info)
    }

    /// Reads, decrypts, and records all votes for a proposal.
    ///
    /// Workflow:
    /// 1. Checks the shared [`VoteFactory`] via the `Mutex`; if it is already
    ///    marked complete, the function returns early.
    /// 2. Fetches the total on-chain vote count from [`Governance`].
    /// 3. Iterates over each vote index:
    ///    - reads the raw on-chain vote,
    ///    - converts it into a [`crate::proposal::VoteDecision`] using the provided encryption
    ///      private key `sk` and `proposal_id`,
    ///    - stores the decision into the [`VoteFactory`] by index.
    /// 4. After all decisions are stored
    ///    compute and attach token-based weights.
    ///
    /// Errors if:
    /// - the mutex is poisoned,
    /// - the vote count does not fit into `u64`,
    /// - any underlying governance RPC call fails,
    /// - or decryption / interpretation fails in a way not mapped to
    ///   [`crate::proposal::VoteDecision::Invalid`].
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

        self.parse_votes_weight(proposal_id, vote_factory.clone())
            .await?;

        Ok(())
    }

    /// Reads, decrypts, and records all votes for a proposal.
    ///
    /// Workflow:
    /// 1. Checks the shared [`VoteFactory`] via the `Mutex`; if it is already
    ///    marked complete, the function returns early.
    /// 2. Fetches the total on-chain vote count from [`Governance`].
    /// 3. Iterates over each vote index:
    ///    - reads the raw on-chain vote,
    ///    - converts it into a [`VoteDecision`] using the provided encryption
    ///      private key `sk` and `proposal_id`,
    ///    - stores the decision into the [`VoteFactory`] by index.
    /// 4. After all decisions are stored, calls [`Self::parse_votes_weight`] to
    ///    compute and attach token-based weights.
    ///
    /// Errors if:
    /// - the mutex is poisoned,
    /// - the vote count does not fit into `u64`,
    /// - any underlying governance RPC call fails,
    /// - or decryption / interpretation fails in a way not mapped to
    ///   [`VoteDecision::Invalid`].
    async fn parse_votes_weight(
        &self,
        proposal_id: B256,
        vote_factory: Arc<Mutex<VoteFactory>>,
    ) -> Result<()> {
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

        let accurate_block_on_gov_chain = self
            .governance
            .get_accurate_proposal_creation_block_number(proposal_id)
            .await?;

        let mut total_votes_by_chain: Vec<(U256, U256)> = Vec::new();
        let token_network_configs = self
            .governance_enclave
            .get_all_supported_token_network_configs(accurate_block_on_gov_chain)
            .await?;

        for (chain_id, token_network_config) in token_network_configs {
            let base_url = token_network_config
                .rpcUrls
                .get(0)
                .ok_or_else(|| anyhow!("no rpc URL found in token_network_configs"))?;

            let rpc_url = config::create_rpc_url(base_url, chain_id)?;

            let nearest_block_to_proposal_creation =
                find_block_by_timestamp::<Ethereum>(&rpc_url, proposal_ts).await?;

            let token_instance = TokenInstance::<Ethereum>::new(
                &rpc_url,
                token_network_config.tokenAddress.to_string().as_ref(),
            )?;

            let total_votes = token_instance
                .get_total_votes(nearest_block_to_proposal_creation)
                .await?;

            total_votes_by_chain.push((chain_id, total_votes));
        }

        let mut updates: Vec<WeightVoteDecision> = Vec::new();
        for (chain_id, address_vote_map) in votes_by_chain {
            let token_network_configs = self
                .governance_enclave
                .get_token_network_config(chain_id, accurate_block_on_gov_chain)
                .await?;

            let base_url = token_network_configs
                .rpcUrls
                .get(0)
                .ok_or_else(|| anyhow!("no rpc URL found in token_network_configs"))?;

            let rpc_url = config::create_rpc_url(base_url, chain_id)?;

            let nearest_block_to_proposal_creation =
                find_block_by_timestamp::<Ethereum>(&rpc_url, proposal_ts).await?;

            let delegation_contract_address = self
                .governance
                .get_delegation_contract_address(chain_id.clone(), proposal_id)
                .await?;

            let delegation = Delegation::<Ethereum>::new(
                &rpc_url,
                delegation_contract_address.to_string().as_ref(),
            )?;

            let token_instance = TokenInstance::<Ethereum>::new(
                &rpc_url,
                token_network_configs.tokenAddress.to_string().as_ref(),
            )?;

            for (delegator_or_voter, decision) in address_vote_map {
                if let Some(_dgtr) = decision.get_delegator_address() {
                    let delegatee_as_per_contract = delegation
                        .get_delegatee(_dgtr.clone(), nearest_block_to_proposal_creation)
                        .await?;

                    if delegatee_as_per_contract == Address::ZERO
                        || delegatee_as_per_contract == decision.get_voter_address()
                    {
                        // this is valid vote,
                    } else {
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

            for (chain_id, total_votes) in total_votes_by_chain {
                vf.set_total_votes_by_chain(chain_id, total_votes)?;
            }
            vf.set_complete(true);
        }

        Ok(())
    }
}
