use alloy::{
    network::Network,
    primitives::{Address, B256, U256},
    providers::{Provider, RootProvider},
    rpc::types::Filter,
    signers::k256::sha2::{Digest, Sha256},
    sol,
    sol_types::{SolEvent, SolValue},
};
use anyhow::{Result, anyhow};
use url::Url;

use crate::{
    config,
    governance::IGovernance::{
        ProposalTimeInfo, Vote, getAllVoteInfoReturn, getProposalHashesReturn,
    },
};
use serde::{Deserialize, Serialize};

sol! {

    #[sol(rpc)]
    interface IGovernance {

        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        struct Vote {
            address voter;
            address delegator; // address(0) if not delegated
            uint256 delegatorChainId; // 0 if not delegated
            bytes voteEncrypted;
        }

        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        struct ProposalTimeInfo {
            uint256 proposedTimestamp;
            uint256 voteActivationTimestamp;
            uint256 voteDeadlineTimestamp;
            uint256 proposalDeadlineTimestamp;
        }

        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        struct SubmitResultInputParams {
            bytes kmsSig;
            bytes enclavePubKey;
            bytes enclaveSig;
            bytes resultData;
            bytes voteDecryptionKey;
        }

        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        struct VoteDecisionResult {
            uint256 yes;
            uint256 no;
            uint256 abstain;
            uint256 noWithVeto;
            uint256 totalVotingPower;
        }

        // Delegation chain IDs
        #[derive(Debug)]
        function getDelegationChainIdsLength() external view returns (uint256);

        function getAllDelegationChainIds() external view returns (uint256[] memory);

        // Proposal timing config
        #[derive(Debug)]
        function getProposalTimingConfig() external view returns (uint256 voteActivationDelay, uint256 voteDuration, uint256 proposalDuration);

        // Proposal hashes
        #[derive(Debug)]
        function getProposalHashes(bytes32 _proposalId) external view returns (bytes32, bytes32, bytes32);

        #[derive(Debug)]
        function getAllVoteInfo(bytes32 _proposalId) external view returns (Vote[] memory votes, uint256 voteCount, bytes32 voteHash);

        #[derive(Debug)]
        function getVoteCount(bytes32 _proposalId) external view returns (uint256);

        #[derive(Debug)]
        function getProposalTimeInfo(bytes32 _proposalId) public view returns (ProposalTimeInfo memory);

        function getSingleVoteInfo(bytes32 _proposalId, uint256 idx) external view returns (Vote memory);

        function getGovernanceDelegation(uint256 _chainId) external view returns (address);

        function getVoteHash(bytes32 _proposalId) public view returns (bytes32);

        #[derive(Debug)]
        event ProposalCreated(
            bytes32 indexed proposalId,
            address indexed proposer,
            uint256 nonce,
            address[] targets,
            uint256[] values,
            bytes[] calldatas,
            string title,
            string description,
            ProposalTimeInfo proposalTimeInfo
        );
    }
}

/// Client for interacting with an on-chain governance contract.
///
/// This type wraps an Alloy [`RootProvider`] and the governance contract
/// address, and exposes high-level helpers for reading governance state.
#[derive(Debug, Clone)]
pub struct Governance<N: Network> {
    provider: RootProvider<N>,
    governance: Address,
    #[allow(unused)]
    governance_enclave: Address,
    gov_chain_rpc_url: String,
}

impl<N: Network> Governance<N> {
    /// Constructs a new governance client for the given contract and enclave.
    ///
    /// - `gov_chain_rpc_url` – RPC endpoint for the governance chain.
    /// - `governance_address` – address of the governance contract.
    /// - `governance_enclave_address` – address of the governance enclave
    ///   (used when computing contract data hashes).
    ///
    /// Returns an error if the RPC URL or either address cannot be parsed.
    pub fn new(
        gov_chain_rpc_url: &str,
        governance_address: &str,
        governance_enclave_address: &str,
    ) -> Result<Self> {
        let url = Url::parse(gov_chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let governance = governance_address.parse()?;
        Ok(Self {
            gov_chain_rpc_url: gov_chain_rpc_url.into(),
            provider,
            governance,
            governance_enclave: governance_enclave_address.parse()?,
        })
    }

    /// Returns the underlying governance contract address.
    pub fn get_address(&self) -> Address {
        self.governance
    }

    /// Fetches the timing information for a specific proposal.
    ///
    /// This calls `getProposalTimeInfo` on the governance contract and returns
    /// the corresponding [`ProposalTimeInfo`]. Useful for determining when
    /// voting starts and ends for `proposal_id`.
    pub async fn get_proposal_timing_info(&self, proposal_id: B256) -> Result<ProposalTimeInfo> {
        log::debug!(
            "Fetching Proposal timing info for proposal: {}",
            proposal_id
        );
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let timing_info = i_governance
            .getProposalTimeInfo(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "Proposal timing info for proposal: {} = {:?}",
            proposal_id,
            timing_info
        );
        Ok(timing_info)
    }

    /// Fetches the on-chain vote count for a specific proposal.
    ///
    /// This calls `getVoteCount` on the governance contract and returns the
    /// raw count as a [`U256`].
    pub async fn get_vote_count(&self, proposal_id: B256) -> Result<U256> {
        log::debug!("Fetching vote count info for proposal: {}", proposal_id);
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let vote_count = i_governance
            .getVoteCount(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "Vote count for proposal: {} = {:?}",
            proposal_id,
            vote_count
        );

        Ok(vote_count)
    }

    /// Fetches all vote information for a proposal in a single call.
    ///
    /// This is a thin wrapper around `getAllVoteInfo` and returns the raw
    /// Solidity return type. It may be expensive or fail on some providers
    /// due to gas or response size limits, so prefer paginated or local
    /// aggregation where possible.
    #[deprecated(note = "This call may fail at runtime; handle the Result.")]
    pub async fn get_all_vote_info(&self, proposal_id: B256) -> Result<getAllVoteInfoReturn> {
        let i_governance = IGovernance::new(self.governance, &self.provider);
        return i_governance
            .getAllVoteInfo(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err));
    }

    /// Fetches a single vote for a proposal at the given index.
    ///
    /// This calls `getSingleVoteInfo` and returns the raw [`Vote`] struct
    /// corresponding to `idx` for the given `proposal_id`.
    pub async fn get_single_vote(&self, proposal_id: B256, idx: U256) -> Result<Vote> {
        log::debug!(
            "Fetching vote info for proposal: {} idx: {}",
            proposal_id,
            idx
        );
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let single_vote = i_governance
            .getSingleVoteInfo(proposal_id, idx)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "vote info for proposal: {} idx: {} = {:?}",
            proposal_id,
            idx,
            single_vote
        );
        Ok(single_vote)
    }

    /// Resolves the delegation contract address for a given `chain_id` at the
    /// time a proposal was created.
    ///
    /// This first finds an accurate creation block for `proposal_id` and then
    /// queries `getGovernanceDelegation(chain_id)` at that block, so the
    /// returned address reflects the historical configuration at creation time.
    pub async fn get_delegation_contract_address(
        &self,
        chain_id: U256,
        proposal_id: B256,
    ) -> Result<Address> {
        log::debug!(
            "Fetching delegation contract address for chain_id: {}",
            chain_id
        );
        let block_number = self
            .get_accurate_proposal_creation_block_number(proposal_id)
            .await?;

        let i_governance = IGovernance::new(self.governance, &self.provider);
        let addr = i_governance
            .getGovernanceDelegation(chain_id)
            .call()
            .block(block_number.into())
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "delegation contract address for chain_id {} = {}",
            chain_id,
            addr
        );
        Ok(addr)
    }

    /// Resolves the delegation contract address for a given `chain_id` at the
    /// time a proposal was created.
    ///
    /// This first finds an accurate creation block for `proposal_id` and then
    /// queries `getGovernanceDelegation(chain_id)` at that block, so the
    /// returned address reflects the historical configuration at creation time.
    #[deprecated(note = "Compute the values locally")]
    pub async fn get_proposal_hash(&self, proposal_id: B256) -> Result<getProposalHashesReturn> {
        log::debug!("Fetching proposal hashes for proposal_id: {}", proposal_id);
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let hashes = i_governance
            .getProposalHashes(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!("proposal hashes for {} = {:?}", proposal_id, hashes);
        Ok(hashes)
    }

    /// Finds a more accurate proposal creation block number using logs.
    ///
    /// This uses the proposal's `proposedTimestamp` and a binary search on
    /// block timestamps to find an approximate block, then narrows it by
    /// scanning `ProposalCreated` logs around that block. The resulting
    /// block number is suitable for historical `block`-tagged RPC queries.
    pub async fn get_accurate_proposal_creation_block_number(
        &self,
        proposal_id: B256,
    ) -> Result<u64> {
        let proposal_time_info = self.get_proposal_timing_info(proposal_id).await?;
        let approximate_block_number = config::find_block_by_timestamp::<N>(
            &self.gov_chain_rpc_url,
            proposal_time_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        let block_number = self
            .get_blocknumber_for_proposal_from_logs(proposal_id, approximate_block_number)
            .await?;

        Ok(block_number)
    }

    /// Computes a deterministic hash over governance-related contract data
    /// at the time a proposal was created.
    ///
    /// The hash is initialized with the governance enclave address and then
    /// incrementally updated with each delegation chain ID and its delegation
    /// contract address, all evaluated at the proposal's creation block.
    ///
    /// This can be used to attest to the governance configuration that was
    /// in effect when the proposal was created.
    pub async fn compute_contract_data_hash(&self, proposal_id: B256) -> Result<B256> {
        let block_number = self
            .get_accurate_proposal_creation_block_number(proposal_id)
            .await?;
        let mut init_contract_data_hash = {
            sol! {struct Input {address a; }}
            let input = Input {
                a: self.governance_enclave,
            };
            let h = Sha256::digest(input.abi_encode());
            B256::from_slice(&h)
        };
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let delegation_chainids = i_governance
            .getAllDelegationChainIds()
            .call()
            .block(block_number.into())
            .await?;

        for delegation_chain in delegation_chainids {
            let delegation_contract = i_governance
                .getGovernanceDelegation(delegation_chain)
                .call()
                .block(block_number.into())
                .await?;
            sol! {struct Input {bytes32 currentHash; uint256 chainId; address delegation;}}
            let input = Input {
                currentHash: init_contract_data_hash,
                chainId: delegation_chain,
                delegation: delegation_contract,
            };
            let h = Sha256::digest(input.abi_encode());
            init_contract_data_hash = B256::from_slice(&h);
        }
        Ok(init_contract_data_hash)
    }

    /// Fetches the vote hash for a proposal directly from the contract.
    ///
    /// Intended primarily for debugging and verification of locally computed
    /// hashes, since it requires an additional RPC round-trip.
    #[deprecated(note = "This is to be only used fur debugging")]
    pub async fn get_vote_hash_from_contract(&self, proposal_id: B256) -> Result<B256> {
        log::debug!("Fetching vote hash for proposal_id: {}", proposal_id);
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let vote_hash = i_governance
            .getVoteHash(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!("vote hash for {} = {}", proposal_id, vote_hash);
        Ok(vote_hash)
    }

    /// Derives the exact block number at which a proposal was created by
    /// inspecting `ProposalCreated` logs.
    ///
    /// A [`Filter`] is built around an approximate block range, and the first
    /// matching `ProposalCreated` log for `proposal_id` is used to extract
    /// the block number.
    ///
    /// Returns an error if no matching log is found in the range or if the
    /// log is missing a `block_number` field.
    pub async fn get_blocknumber_for_proposal_from_logs(
        &self,
        proposal_id: B256,
        approximate_block_number: u64,
    ) -> Result<u64> {
        let filter = Filter::new()
            .address(self.governance)
            .event_signature(IGovernance::ProposalCreated::SIGNATURE_HASH)
            .topic1(proposal_id)
            .from_block(approximate_block_number - 100)
            .to_block(approximate_block_number + 100);

        let logs = self.provider.get_logs(&filter).await?;

        let log = logs
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow!(
                "no ProposalCreated log found for proposal {proposal_id:?} around block {approximate_block_number}"
            )
        })?;

        let block_number = log.block_number.ok_or_else(|| {
            anyhow!("log for proposal {proposal_id:?} is missing block_number field")
        })?;

        Ok(block_number)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{network::Ethereum, primitives::U256};
    use anyhow::Result;

    use crate::{
        config::{create_gov_chain_rpc_url, create_rpc_url, find_block_by_timestamp, get_config},
        governance::{Governance, IGovernance::ProposalTimeInfo},
    };

    use dotenvy::dotenv;

    async fn timing_info() -> Result<ProposalTimeInfo> {
        dotenv().ok();
        let cfg = get_config()?;
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        let governance = Governance::<Ethereum>::new(
            &create_gov_chain_rpc_url()?,
            &cfg.governance_contract,
            &cfg.governance_enclave,
        )?;
        let timing_info = governance
            .get_proposal_timing_info(proposal_id.parse()?)
            .await?;

        Ok(timing_info)
    }

    #[tokio::test]
    async fn proposal_block_number() -> Result<()> {
        dotenv().ok();
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        let cfg = get_config()?;
        let timing_info = timing_info().await?;

        let governance = Governance::<Ethereum>::new(
            &create_gov_chain_rpc_url()?,
            &cfg.governance_contract,
            &cfg.governance_enclave,
        )?;

        let approximate_block_number = find_block_by_timestamp::<Ethereum>(
            &create_gov_chain_rpc_url()?,
            timing_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        let example_block_number = governance
            .get_blocknumber_for_proposal_from_logs(proposal_id.parse()?, approximate_block_number)
            .await?;

        assert_eq!(example_block_number >= 214026482, true);

        Ok(())
    }

    #[tokio::test]
    async fn read_search_nearest_block_1() -> Result<()> {
        let timing_info = timing_info().await?;

        let rpc_url = create_rpc_url(
            "https://arb-sepolia.g.alchemy.com/v2/".into(),
            U256::from(421614),
        )?;

        let nearest_block_to_proposal_creation = find_block_by_timestamp::<Ethereum>(
            rpc_url.as_ref(),
            timing_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        println!(
            "nearest_block_to_proposal_creation: {}",
            nearest_block_to_proposal_creation
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_search_nearest_block_2() -> Result<()> {
        let timing_info = timing_info().await?;
        let rpc_url = create_rpc_url(
            "https://arb-sepolia.g.alchemy.com/v2/".into(),
            U256::from(11155111),
        )?;

        let nearest_block_to_proposal_creation = find_block_by_timestamp::<Ethereum>(
            rpc_url.as_ref(),
            timing_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        println!(
            "nearest_block_to_proposal_creation: {}",
            nearest_block_to_proposal_creation
        );
        Ok(())
    }
}
