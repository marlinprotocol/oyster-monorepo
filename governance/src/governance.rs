use alloy::{
    network::Network,
    primitives::{Address, B256, U256},
    providers::RootProvider,
    signers::k256::sha2::{Digest, Sha256},
    sol,
    sol_types::SolValue,
};
use anyhow::Result;
use url::Url;

use crate::governance::IGovernance::{
    ProposalTimeInfo, Vote, getAllVoteInfoReturn, getProposalHashesReturn,
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

#[derive(Debug, Clone)]
pub struct Governance<N: Network> {
    provider: RootProvider<N>,
    governance: Address,
    #[allow(unused)]
    governance_enclave: Address,
}

impl<N: Network> Governance<N> {
    pub fn new(
        gov_chain_rpc_url: &str,
        governance_address: &str,
        governance_enclave_address: &str,
    ) -> Result<Self> {
        let url = Url::parse(gov_chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let governance = governance_address.parse()?;
        Ok(Self {
            provider,
            governance,
            governance_enclave: governance_enclave_address.parse()?,
        })
    }

    pub fn get_address(&self) -> Address {
        self.governance
    }

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

    #[deprecated(note = "This call may fail at runtime; handle the Result.")]
    pub async fn get_all_vote_info(&self, proposal_id: B256) -> Result<getAllVoteInfoReturn> {
        let i_governance = IGovernance::new(self.governance, &self.provider);
        return i_governance
            .getAllVoteInfo(proposal_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err));
    }

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

    pub async fn get_delegation_contract_address(&self, chain_id: U256) -> Result<Address> {
        log::debug!(
            "Fetching delegation contract address for chain_id: {}",
            chain_id
        );
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let addr = i_governance
            .getGovernanceDelegation(chain_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "delegation contract address for chain_id {} = {}",
            chain_id,
            addr
        );
        Ok(addr)
    }

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

    #[deprecated(note = "Check this if meets all the requirements")]
    pub async fn compute_contract_data_hash(&self) -> Result<B256> {
        let mut init_contract_data_hash = {
            sol! {struct Input {address a; }}
            let input = Input {
                a: self.governance_enclave,
            };
            let h = Sha256::digest(input.abi_encode());
            B256::from_slice(&h)
        };
        let i_governance = IGovernance::new(self.governance, &self.provider);
        let delegation_chainids = i_governance.getAllDelegationChainIds().call().await?;

        for delegation_chain in delegation_chainids {
            let delegation_contract = i_governance
                .getGovernanceDelegation(delegation_chain)
                .call()
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

    #[deprecated(note = "don't use this, instead compute")]
    pub async fn get_vote_hash(&self, proposal_id: B256) -> Result<B256> {
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
}

#[cfg(test)]
mod tests {
    use alloy::network::Ethereum;
    use anyhow::Result;

    use crate::{
        config::{find_block_by_timestamp, get_config},
        governance::{Governance, IGovernance::ProposalTimeInfo},
    };

    use dotenvy::dotenv;

    async fn timing_info() -> Result<ProposalTimeInfo> {
        let cfg = get_config()?;
        dotenv().ok();
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        let governance = Governance::<Ethereum>::new(
            &cfg.gov_chain_rpc_url,
            &cfg.governance_contract,
            &cfg.governance_enclave,
        )?;
        let timing_info = governance
            .get_proposal_timing_info(proposal_id.parse()?)
            .await?;

        Ok(timing_info)
    }

    #[tokio::test]
    async fn read_search_nearest_block_1() -> Result<()> {
        dotenv().ok();
        let cfg = get_config()?;
        let timing_info = timing_info().await?;

        let nearest_block_to_proposal_creation = find_block_by_timestamp::<Ethereum>(
            &cfg.other_rpc_urls.get("421614").unwrap(),
            timing_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        log::info!(
            "nearest_block_to_proposal_creation: {}",
            nearest_block_to_proposal_creation
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_search_nearest_block_2() -> Result<()> {
        dotenv().ok();
        let cfg = get_config()?;
        let timing_info = timing_info().await?;

        let nearest_block_to_proposal_creation = find_block_by_timestamp::<Ethereum>(
            &cfg.other_rpc_urls.get("11155111").unwrap(),
            timing_info.proposedTimestamp.to::<u64>(),
        )
        .await?;

        log::info!(
            "nearest_block_to_proposal_creation: {}",
            nearest_block_to_proposal_creation
        );
        Ok(())
    }
}
