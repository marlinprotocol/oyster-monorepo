use alloy::{
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    signers::{SignerSync, local::PrivateKeySigner as SigningPrivateKey},
    sol,
    sol_types::SolValue,
};

use anyhow::{Result, anyhow};
use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};
use serde::{Deserialize, Serialize};

use crate::governance::IGovernance::Vote;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    Yes((GovernanceVote, InferredVote)),
    No((GovernanceVote, InferredVote)),
    Abstain((GovernanceVote, InferredVote)),
    NoWithVeto((GovernanceVote, InferredVote)),
    Invalid(GovernanceVote),
}

impl VoteDecision {
    pub fn get_chain_id(&self) -> Option<U256> {
        let id = match self {
            VoteDecision::Yes(v)
            | VoteDecision::No(v)
            | VoteDecision::Abstain(v)
            | VoteDecision::NoWithVeto(v) => Some(v.1.source_chain_id),

            VoteDecision::Invalid(_) => None,
        };

        id
    }

    pub fn get_delegator_address(&self) -> Option<Address> {
        let delegator = match self {
            VoteDecision::Yes(a) => a.0.delegator,
            VoteDecision::No(a) => a.0.delegator,
            VoteDecision::Abstain(a) => a.0.delegator,
            VoteDecision::NoWithVeto(a) => a.0.delegator,
            VoteDecision::Invalid(vote) => vote.delegator,
        };

        if delegator == Address::ZERO {
            None
        } else {
            Some(delegator)
        }
    }

    pub fn get_voter_address(&self) -> Address {
        match self {
            VoteDecision::Yes(a) => a.0.voter,
            VoteDecision::No(a) => a.0.voter,
            VoteDecision::Abstain(a) => a.0.voter,
            VoteDecision::NoWithVeto(a) => a.0.voter,
            VoteDecision::Invalid(vote) => vote.voter,
        }
    }
}

sol! {

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct EncryptedVote{
        bytes encrypted_vote;
        bytes signature;
    }

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct InferredVote {
        uint256 decision;
        uint256 source_chain_id;
        bytes32 proposal_hash;
    }

}

impl InferredVote {
    pub fn to_governance_vote(
        &self,
        sk: SigningPrivateKey,
        pk: EncryptionPublicKey,
        delegator: Address,
    ) -> Result<GovernanceVote> {
        let inferred_vote_bytes = self.abi_encode().clone();
        let encrypted_vote_bytes = encrypt_ecies(&pk.serialize(), &inferred_vote_bytes)?;

        let digest = keccak256(&encrypted_vote_bytes);
        let signature = sk.sign_hash_sync(&digest)?.as_bytes();

        let encrypted_vote = EncryptedVote {
            encrypted_vote: encrypted_vote_bytes.into(),
            signature: signature.into(),
        };

        let gov_vote = GovernanceVote {
            voter: sk.address(),
            delegator,
            delegatorChainId: self.source_chain_id.clone(),
            voteEncrypted: encrypted_vote.abi_encode().into(),
        };

        return Ok(gov_vote);
    }
}

pub type GovernanceVote = Vote;

impl GovernanceVote {
    pub fn to_vote_decision(&self, sk: EncryptionPrivateKey, proposal_id: B256) -> VoteDecision {
        match self._to_vote_decision(sk, proposal_id) {
            Ok(a) => a,
            _ => VoteDecision::Invalid(self.clone()),
        }
    }
    fn _to_vote_decision(
        &self,
        sk: EncryptionPrivateKey,
        proposal_id: B256,
    ) -> Result<VoteDecision> {
        let encrypted_vote = EncryptedVote::abi_decode(&self.voteEncrypted)?;
        let digest = keccak256(&encrypted_vote.encrypted_vote);
        let sig_bytes: &Bytes = &encrypted_vote.signature; // ABI `bytes`
        let sig = Signature::try_from(sig_bytes.as_ref())?; // <- &[u8]

        let recovered = sig.recover_address_from_prehash(&digest)?;
        if recovered != self.voter {
            return Ok(VoteDecision::Invalid(self.clone()));
        }

        let decrypted_vote = decrypt_ecies(&sk.serialize(), &encrypted_vote.encrypted_vote)?;
        let inferred_vote = InferredVote::abi_decode(&decrypted_vote)?;

        if inferred_vote.proposal_hash.ne(&proposal_id) {
            return Ok(VoteDecision::Invalid(self.clone()));
        }

        if inferred_vote.decision.eq(&U256::from(1)) {
            return Ok(VoteDecision::Yes((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(2)) {
            return Ok(VoteDecision::No((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(3)) {
            return Ok(VoteDecision::NoWithVeto((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(4)) {
            return Ok(VoteDecision::Abstain((self.clone(), inferred_vote)));
        }

        return Ok(VoteDecision::Invalid(self.clone()));
    }
}

pub fn decrypt_ecies(receiver_priv: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let result = ecies::decrypt(receiver_priv, msg).map_err(|e| anyhow!(e))?;
    Ok(result)
}

pub fn encrypt_ecies(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let result = ecies::encrypt(receiver_pub, msg).map_err(|e| anyhow!(e))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::kms::{DirtyKMS, KMS};

    use super::*;
    use alloy::{
        primitives::{B256, U256},
        signers::{k256::SecretKey as KSec, local::PrivateKeySigner as SigningPrivateKey},
    };
    use anyhow::Ok;
    use ecies::utils::generate_keypair;
    use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};

    use dotenvy::dotenv;

    fn make_delegatee_signing_key() -> Result<SigningPrivateKey> {
        // Load .env if present (no-op in production if you don't ship it)
        dotenv().ok();

        let sk_hex = std::env::var("SIGNING_SK_HEX")?;
        let sk_hex = sk_hex.strip_prefix("0x").unwrap_or(&sk_hex);

        let sk_bytes = hex::decode(sk_hex)?;
        assert!(
            sk_bytes.len() == 32,
            "SIGNING_SK_HEX must decode to 32 bytes"
        );

        let ksec = KSec::from_slice(&sk_bytes).expect("valid secp256k1 scalar");
        Ok(SigningPrivateKey::from(ksec))
    }

    fn make_encryption_keypair() -> (EncryptionPrivateKey, EncryptionPublicKey) {
        generate_keypair()
    }

    fn mk_inferred(decision: u64, chain_id: u64, proposal_hash: B256) -> InferredVote {
        InferredVote {
            decision: U256::from(decision),
            source_chain_id: U256::from(chain_id),
            proposal_hash,
        }
    }

    fn assert_roundtrip(decision_num: u64) -> Result<()> {
        dotenv().ok();
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        // Separate keys by role
        let signing_sk = SigningPrivateKey::random();
        let (enc_sk, enc_pk) = make_encryption_keypair();

        let iv = mk_inferred(decision_num, 777, proposal_id.parse()?);

        let gv = iv
            .to_governance_vote(signing_sk.clone(), enc_pk.clone(), Address::ZERO)
            .expect("build gov vote");

        // Correct decryption key → should recover the same decision
        let out = gv.to_vote_decision(enc_sk.clone(), proposal_id.parse()?);
        let expected = match decision_num {
            1 => VoteDecision::Yes((gv.clone(), iv.clone())),
            2 => VoteDecision::No((gv.clone(), iv.clone())),
            3 => VoteDecision::NoWithVeto((gv.clone(), iv.clone())),
            4 => VoteDecision::Abstain((gv.clone(), iv.clone())),
            _ => VoteDecision::Invalid(gv.clone()),
        };

        assert_eq!(out, expected, "decision {} must roundtrip", decision_num);

        Ok(())
    }

    #[test]
    fn roundtrip_yes_no_veto_abstain() -> Result<()> {
        assert_roundtrip(1)?;
        assert_roundtrip(2)?;
        assert_roundtrip(3)?;
        assert_roundtrip(4)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_enc_vote_generation() -> Result<()> {
        dotenv().ok();
        let proposal_id = std::env::var("TEST_PROPOSAL_ID")?;

        let delegatee_signing_key = make_delegatee_signing_key()?;
        #[allow(unused)]
        let random_delegator = SigningPrivateKey::random().address();

        let enc_pk = DirtyKMS::default()
            .get_proposal_public_key(proposal_id.parse()?)
            .await?;

        let iv = InferredVote {
            decision: U256::from(2),
            source_chain_id: U256::from(421614),
            proposal_hash: proposal_id.parse()?,
        };
        let gv = iv
            .to_governance_vote(
                delegatee_signing_key.clone(),
                enc_pk.clone(),
                delegatee_signing_key.address(),
            )
            .expect("build gov vote");

        println!("{:?}", gv);

        Ok(())
    }

    #[tokio::test]
    async fn test_fe_generated_vote() -> Result<()> {
        let proposal_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse()?;
        let vote = GovernanceVote {
            voter: "0x868683A80eA3038fbcfc1Cc0C0b4078de2ECaF92".parse()?,
            delegator: "0x0000000000000000000000000000000000000000".parse()?,
            delegatorChainId: "421614".parse()?,
            voteEncrypted: "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c104aa2253867e3e5cc018411964541c92cb75a7f6af83477e452b2ad5017c566bc6ba8cea26ca7764ba1de886d00d3b7c80ad985cb0fde45b484c8ca66f3267ea72e57c8a8e06ea8beeca5ecd7c9e8a55deaf540a1b506643e3d3e7dfd176901c3f4c8b4bb20ecbf4708667efbb7acab90c3219cc21995c296bf4c95f1fd11446288ead9955b10a351cbad7a645f77ed8b873ce00f9ff03da177d3463bb21da5cc280efd2b66375313e72940da4bb9b53750741d82a6950417a14e65ee6528a852e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041d6141ed465fcd80e8146997600955f190d69b999791f83676872a307d6ab60953ad8583f9ea2c1ff5ddedcece3fdcb9457a6b0d20765833f80aa179d52269a161c00000000000000000000000000000000000000000000000000000000000000".parse()?,
        };

        let bytes_vec =
            hex::decode("b2d338d9a74c00d314fb2456cce8f790618281085812c29e6d247d1dde5e67d8")?;
        let sk_bytes: [u8; 32] = bytes_vec
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))?;

        let sk = EncryptionPrivateKey::parse(&sk_bytes).map_err(|e| anyhow!(e))?;

        let inferred_vote = vote.to_vote_decision(sk, proposal_id);

        println!("{:?}", inferred_vote);

        Ok(())
    }

    #[test]
    fn test_decode_encrypted_vote() -> Result<()> {
        let enc_vote: Bytes = "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c104aa2253867e3e5cc018411964541c92cb75a7f6af83477e452b2ad5017c566bc6ba8cea26ca7764ba1de886d00d3b7c80ad985cb0fde45b484c8ca66f3267ea72e57c8a8e06ea8beeca5ecd7c9e8a55deaf540a1b506643e3d3e7dfd176901c3f4c8b4bb20ecbf4708667efbb7acab90c3219cc21995c296bf4c95f1fd11446288ead9955b10a351cbad7a645f77ed8b873ce00f9ff03da177d3463bb21da5cc280efd2b66375313e72940da4bb9b53750741d82a6950417a14e65ee6528a852e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041d6141ed465fcd80e8146997600955f190d69b999791f83676872a307d6ab60953ad8583f9ea2c1ff5ddedcece3fdcb9457a6b0d20765833f80aa179d52269a161c00000000000000000000000000000000000000000000000000000000000000".parse()?;
        let enc_vote = EncryptedVote::abi_decode(&enc_vote)?;

        println!("{:?}", enc_vote);

        Ok(())
    }
}
