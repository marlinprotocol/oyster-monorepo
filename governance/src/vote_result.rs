use crate::governance::IGovernance::{SubmitResultInputParams, VoteDecisionResult};
use crate::kms::kms::KMS;
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

/// Aggregates weighted votes for a single proposal and produces on-chain-ready results.
///
/// `VoteAggregator` is responsible for:
/// - summing weighted votes into a [`VoteDecisionResult`],
/// - producing enclave and KMS signatures,
/// - building the ABI-encoded result payload,
/// - and packaging everything into [`SubmitResultInputParams`] that can be
///   submitted to the governance contract.
///
/// It does **not** perform any chain reads itself; instead it operates on:
/// - a precomputed map of weighted votes, and
/// - a KMS handle used to derive encryption-related artifacts.
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
    /// Creates a new [`VoteAggregator`] for a given proposal and image.
    ///
    /// - `proposal_id` – the governance proposal being finalized.
    /// - `image_id` – identifier of the attested image / circuit in the enclave/KMS flow.
    /// - `weighted_votes` – reference to a map of `chain_id -> (address -> WeightVoteDecision)`,
    ///   typically produced by a [`crate::vote_factory::VoteFactory`] or similar component.
    /// - `kms` – shared handle to a [`KMS`] implementation used to fetch signatures
    ///   and decryption material.
    /// - `contract_data_preimage` – preimage containing governance-related contract
    ///   data used to derive the `contract_data_hash`.
    ///
    /// A fresh transient signing key is generated internally and used to sign
    /// enclave messages for this aggregator instance.
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

    /// Computes the aggregate vote tallies for the current proposal.
    ///
    /// Iterates over all [`WeightVoteDecision`] entries in `weighted_votes` and:
    /// - sums weights for `Yes`, `No`, `Abstain`, and `NoWithVeto`,
    /// - ignores [`crate::proposal::VoteDecision::Invalid`] entries,
    /// - accumulates `totalVotingPower` as the sum of all counted weights.
    ///
    /// Returns a [`VoteDecisionResult`] suitable for:
    /// - signing by the enclave,
    /// - embedding into the final `resultData` payload.
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

    /// Requests a KMS signature for this proposal.
    ///
    /// Calls [`KMS::generate_kms_sig`] with:
    /// - the `image_id`,
    /// - the enclave public key returned by [`Self::get_enclave_pubkey`],
    /// - the `proposal_id`.
    ///
    /// Returns the raw signature bytes produced by the KMS. Errors if the
    /// underlying KMS call fails.
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

    /// Returns the enclave's public key bytes for this aggregation session.
    ///
    /// The key is derived from the internally generated transient signing key
    /// and encoded as raw bytes. This value is included in:
    /// - `enclavePubKey` for [`SubmitResultInputParams`],
    /// - and used by downstream consumers to verify `enclaveSig`.
    pub async fn get_enclave_pubkey(&self) -> Result<Bytes> {
        Ok(self.transient_secret_key.public_key().to_vec().into())
    }

    /// Produces the enclave signature over the voting result.
    ///
    /// Steps:
    /// 1. Computes `contract_data_hash` as `sha256(abi.encode(contract_data_preimage))`.
    /// 2. Constructs a `VotingMessage` containing:
    ///    - `contract_data_hash`,
    ///    - `proposal_id`,
    ///    - the aggregated [`VoteDecisionResult`] from [`Self::get_vote_decision_result`].
    /// 3. Computes `message_hash = sha256(abi.encode(VotingMessage))`.
    /// 4. Signs `message_hash` with the transient signing key and returns the
    ///    resulting signature bytes.
    ///
    /// This signature is expected to be verifiable by anyone who knows the
    /// enclave public key and the encoding scheme.
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

    /// Fetches the vote decryption key for this proposal from KMS.
    ///
    /// Delegates to [`KMS::get_proposal_secret_bytes`] using `proposal_id`.
    /// The returned bytes are embedded as `voteDecryptionKey` in
    /// [`SubmitResultInputParams`] and are used by the on-chain / off-chain
    /// logic to decrypt individual votes when appropriate.
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

    /// Builds the ABI-encoded result payload for submission.
    ///
    /// Encodes an internal `(proposal_id, VoteDecisionResult)` pair as:
    ///
    /// `abi.encode(bytes32 proposal_id, VoteDecisionResult)`
    ///
    /// and returns the resulting bytes. These bytes are intended to be used as
    /// `resultData` inside [`SubmitResultInputParams`].
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
