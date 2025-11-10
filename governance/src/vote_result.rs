use crate::governance::IGovernance::{SubmitResultInputParams, VoteDecisionResult};
use crate::kms::KMS;
use crate::vote_factory::WeightVoteDecision;

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::signers::SignerSync;
use alloy::signers::k256::sha2::{Digest, Sha256};
use alloy::signers::local::PrivateKeySigner as SigningPrivateKey;
use alloy::sol;
use alloy::sol_types::SolValue;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

sol! {
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct InternalProposalAndVoteDecisionResult {
        bytes32 proposal_id;
        VoteDecisionResult vote_decision_result;
    }

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct ContractDataPreimage {
        address governance_contract_address;
        uint256 proposed_timestamp;
        bytes32 contract_config_hash;
        bytes32 network_hash;
        bytes32 vote_hash;
    }

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct VotingMessage {
        bytes32 contract_data_hash;
        bytes32 proposal_id;
        VoteDecisionResult vote_decision_result;
    }
}

/// Holds the proposal in focus, a reference to the weighted vote map,
/// and a thread-safe handle to KMS.
pub struct VoteAggregator<'a, K: KMS + Send + Sync> {
    proposal_id: B256,
    image_id: B256,
    weighted_votes: &'a HashMap<U256, HashMap<Address, WeightVoteDecision>>,
    kms: Arc<K>,
    transient_secret_key: SigningPrivateKey,
    contract_data_preimage: ContractDataPreimage,
}

impl<'a, K> VoteAggregator<'a, K>
where
    K: KMS + Send + Sync,
{
    pub fn new(
        proposal_id: B256,
        image_id: B256,
        weighted_votes: &'a HashMap<U256, HashMap<Address, WeightVoteDecision>>,
        kms: Arc<K>,
        contract_data_preimage: ContractDataPreimage,
    ) -> Self {
        Self {
            proposal_id,
            image_id,
            weighted_votes,
            kms,
            transient_secret_key: SigningPrivateKey::random(),
            contract_data_preimage,
        }
    }

    pub fn get_vote_decision_result(&self) -> Result<VoteDecisionResult> {
        let mut yes = U256::ZERO;
        let mut no = U256::ZERO;
        let mut abstain = U256::ZERO;
        let mut no_with_veto = U256::ZERO;
        let mut total_voting_power = U256::ZERO;

        // iterate by reference; do not move out of &self
        for (_pid, address_vote_map) in self.weighted_votes.iter() {
            for (_addr, weighted_vote) in address_vote_map.iter() {
                match &weighted_vote.decision {
                    crate::proposal::VoteDecision::Yes(_) => {
                        yes += weighted_vote.weight.weight;
                        total_voting_power += weighted_vote.weight.weight;
                    }
                    crate::proposal::VoteDecision::No(_) => {
                        no += weighted_vote.weight.weight;
                        total_voting_power += weighted_vote.weight.weight;
                    }
                    crate::proposal::VoteDecision::Abstain(_) => {
                        abstain += weighted_vote.weight.weight;
                        total_voting_power += weighted_vote.weight.weight;
                    }
                    crate::proposal::VoteDecision::NoWithVeto(_) => {
                        no_with_veto += weighted_vote.weight.weight;
                        total_voting_power += weighted_vote.weight.weight;
                    }
                    crate::proposal::VoteDecision::Invalid(_) => {
                        // ignored
                    }
                }
            }
        }

        Ok(VoteDecisionResult {
            yes,
            no,
            abstain,
            noWithVeto: no_with_veto,
            totalVotingPower: total_voting_power,
        })
    }

    pub async fn get_kms_sig(&self) -> Result<Bytes> {
        // Return what KMS produced (don’t drop it)
        let sig = self
            .kms
            .generate_kms_sig(
                self.image_id,
                self.get_enclave_pubkey().await?,
                self.proposal_id,
            )
            .await?;
        Ok(sig)
    }

    pub async fn get_enclave_pubkey(&self) -> Result<Bytes> {
        Ok(self.transient_secret_key.public_key().to_vec().into())
    }

    pub async fn get_enclave_sig(&self) -> Result<Bytes> {
        let contract_data_hash: B256 = {
            let h = Sha256::digest(&self.contract_data_preimage.abi_encode());
            B256::from_slice(&h)
        };

        let message = VotingMessage {
            contract_data_hash,
            proposal_id: self.proposal_id,
            vote_decision_result: self.get_vote_decision_result()?,
        };

        let message_hash: B256 = {
            let h = Sha256::digest(&message.abi_encode());
            B256::from_slice(&h)
        };
        let signature = self
            .transient_secret_key
            .sign_hash_sync(&message_hash)?
            .as_bytes();

        Ok(signature.into())
    }

    pub async fn get_vote_decryption_key(&self) -> Result<Bytes> {
        self.kms.get_proposal_secret_bytes(self.proposal_id).await
    }

    /// abi.encode(bytes32 proposalId, VoteDecisionResult) for `_params.resultData`
    pub fn get_result_data(&self) -> Result<Bytes> {
        let result = InternalProposalAndVoteDecisionResult {
            proposal_id: self.proposal_id,
            vote_decision_result: self.get_vote_decision_result()?,
        };
        Ok(result.abi_encode().into())
    }

    pub async fn get_submit_result_input_params(&self) -> Result<SubmitResultInputParams> {
        let submit_result_input = SubmitResultInputParams {
            kmsSig: self.get_kms_sig().await?,
            enclavePubKey: self.get_enclave_pubkey().await?,
            enclaveSig: self.get_enclave_sig().await?,
            resultData: self.get_result_data()?,
            voteDecryptionKey: self.get_vote_decryption_key().await?,
        };

        Ok(submit_result_input)
    }
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolValue;
    use anyhow::Result;

    use crate::vote_result::ContractDataPreimage;

    #[tokio::test]
    async fn test_contract_preimage_encoding_no_top_level_params() -> Result<()> {
        let contract_data_preimage = ContractDataPreimage {
            governance_contract_address: "0x0000123400001234000012340000123400001234".parse()?,
            proposed_timestamp: "172919243".parse()?,
            contract_config_hash:
                "0x1827900918279009182790091827900918279009182790091827900918279009".parse()?,
            network_hash: "0x8913bdce8913bdce8913bdce8913bdce8913bdce8913bdce8913bdce8913bdce"
                .parse()?,
            vote_hash: "0xab766334ab766334ab766334ab766334ab766334ab766334ab766334ab766334"
                .parse()?,
        };

        println!("{:}", hex::encode(contract_data_preimage.abi_encode()));
        Ok(())
    }
}
