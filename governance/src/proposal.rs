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

/// Unified representation of a single vote decision.
///
/// This enum combines:
///
/// - [`GovernanceVote`] — the raw on-chain vote data.
/// - [`InferredVote`]   — the backend’s interpreted / enriched view of that vote.
///
/// For the “normal” cases, both are present as a pair. For anything that
/// cannot be interpreted into a well-defined decision, the variant
/// [`VoteDecision::Invalid`] holds only the raw [`GovernanceVote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    /// A vote interpreted as **Yes**.
    ///
    /// Tuple contents are `(on_chain, inferred)`:
    /// - `GovernanceVote` – raw on-chain vote.
    /// - `InferredVote`   – backend’s interpretation (e.g. resolved delegations,
    ///   normalized weights, etc.).
    Yes((GovernanceVote, InferredVote)), // 1

    /// A vote interpreted as **No**.
    ///
    /// Tuple contents are `(on_chain, inferred)`.
    No((GovernanceVote, InferredVote)), // 2

    /// A vote interpreted as **No with veto**.
    ///
    /// Tuple contents are `(on_chain, inferred)`.
    NoWithVeto((GovernanceVote, InferredVote)), // 3

    /// A vote interpreted as **Abstain**.
    ///
    /// Tuple contents are `(on_chain, inferred)`.
    Abstain((GovernanceVote, InferredVote)), // 4

    /// Any vote that could not be mapped to a well-defined decision.
    ///
    /// This preserves the raw on-chain [`GovernanceVote`] so callers can:
    /// - inspect the original data,
    /// - log / debug,
    /// - or apply custom fallback logic.
    Invalid(GovernanceVote), // anything else
}

impl VoteDecision {
    /// Returns the underlying on-chain [`GovernanceVote`] for this decision.
    ///
    /// For the interpreted variants (`Yes`, `No`, `NoWithVeto`, `Abstain`),
    /// this is the first element of the `(GovernanceVote, InferredVote)` pair.
    ///
    /// For [`VoteDecision::Invalid`], this returns the raw on-chain vote that
    /// could not be classified.
    pub fn get_on_chain_vote(&self) -> &GovernanceVote {
        match self {
            VoteDecision::Yes(a) => &a.0,
            VoteDecision::No(a) => &a.0,
            VoteDecision::NoWithVeto(a) => &a.0,
            VoteDecision::Abstain(a) => &a.0,
            VoteDecision::Invalid(a) => a,
        }
    }

    /// Returns the source chain ID of the vote, if available.
    ///
    /// Only interpreted votes (`Yes`, `No`, `NoWithVeto`, `Abstain`) carry
    /// backend-derived metadata such as `source_chain_id`, so this method
    /// returns:
    ///
    /// - `Some(chain_id)` for interpreted decisions,
    /// - `None` for [`VoteDecision::Invalid`], since no `InferredVote` exists.
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

    /// Returns the delegator address *if present and non-zero*.
    ///
    /// - For interpreted decisions (`Yes`, `No`, `NoWithVeto`, `Abstain`),
    ///   this is extracted from the underlying [`GovernanceVote`].
    ///
    /// - For [`VoteDecision::Invalid`], the raw on-chain delegator address
    ///   is used.
    ///
    /// A delegator of `Address::ZERO` is treated as “not set” and returns `None`.
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

    /// Returns the original voter address from the on-chain vote.
    ///
    /// All variants, including [`VoteDecision::Invalid`], store a
    /// [`GovernanceVote`], so this method is total and never returns `None`.
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

/// Alias for the raw on-chain vote type.
///
/// This represents a single vote as it exists on-chain, before any
/// backend interpretation or enrichment is applied.
pub type GovernanceVote = Vote;

impl GovernanceVote {
    /// Converts this raw on-chain vote into a high-level [`VoteDecision`].
    ///
    /// This method takes:
    ///
    /// - `sk` – the encryption private key used to decrypt or interpret any
    ///   encrypted payload associated with the vote.
    /// - `proposal_id` – the proposal this vote is associated with, used as
    ///   contextual information for interpretation.
    ///
    /// On success, it returns one of the concrete variants:
    ///
    /// - [`VoteDecision::Yes`]
    /// - [`VoteDecision::No`]
    /// - [`VoteDecision::NoWithVeto`]
    /// - [`VoteDecision::Abstain`]
    ///
    /// When the vote cannot be interpreted (for example due to decryption
    /// errors, malformed data, or unsupported encoding), it falls back to
    /// [`VoteDecision::Invalid`], preserving the original [`GovernanceVote`]
    /// so callers can log, debug, or apply custom handling.
    pub fn to_vote_decision(&self, sk: EncryptionPrivateKey, proposal_id: B256) -> VoteDecision {
        match self._to_vote_decision(sk, proposal_id) {
            Ok(a) => a,
            _ => VoteDecision::Invalid(self.clone()),
        }
    }

    fn _recover(&self) -> Result<Address> {
        let encrypted_vote = EncryptedVote::abi_decode(&self.voteEncrypted)?;
        log::debug!("encrypted vote: {:?}", encrypted_vote);
        let digest = keccak256(&encrypted_vote.encrypted_vote);
        log::debug!("digest: {:?}", hex::encode(digest));
        let sig_bytes: &Bytes = &encrypted_vote.signature; // ABI `bytes`
        log::debug!("sig_bytes: {:?}", hex::encode(sig_bytes));
        let sig = Signature::try_from(sig_bytes.as_ref())?; // <- &[u8]

        let recovered = sig.recover_address_from_prehash(&digest)?;
        Ok(recovered)
    }

    fn _recover_alt(&self) -> Result<Address> {
        let encrypted_vote = EncryptedVote::abi_decode(&self.voteEncrypted)?;
        log::debug!("encrypted vote: {:?}", encrypted_vote);
        let digest = keccak256(&encrypted_vote.encrypted_vote);
        log::debug!("digest: {:?}", hex::encode(digest));
        let digest = hash_eip191_message(&digest.to_vec());
        log::debug!("post digest: {:?}", hex::encode(digest));
        let sig_bytes: &Bytes = &encrypted_vote.signature; // ABI `bytes`
        log::debug!("sig_bytes: {:?}", hex::encode(sig_bytes));
        let sig = Signature::try_from(sig_bytes.as_ref())?; // <- &[u8]

        let recovered = sig.recover_address_from_prehash(&digest)?;
        Ok(recovered)
    }

    fn _to_vote_decision(
        &self,
        sk: EncryptionPrivateKey,
        proposal_id: B256,
    ) -> Result<VoteDecision> {
        log::debug!("Decoding governance vote: {:?}", self);
        let encrypted_vote = EncryptedVote::abi_decode(&self.voteEncrypted)?;

        let recovered = self._recover()?;
        let recovered_alt = self._recover_alt()?;

        if self.voter == recovered || self.voter == recovered_alt {
            // good vote
        } else {
            log::debug!(
                "recovered vote: {}/{} and actual voter: {} are different. Discarding vote",
                recovered,
                recovered_alt,
                self.voter
            );

            return Ok(VoteDecision::Invalid(self.clone()));
        }

        let decrypted_vote = decrypt_ecies(&sk.serialize(), &encrypted_vote.encrypted_vote)?;
        let inferred_vote = InferredVote::abi_decode(&decrypted_vote)?;

        if inferred_vote.proposal_hash.ne(&proposal_id) {
            log::debug!(
                "recovered vote proposal: {} hash doesn't match actual proposal id: {}. Discarding vote",
                inferred_vote.proposal_hash,
                proposal_id
            );
            return Ok(VoteDecision::Invalid(self.clone()));
        }

        if inferred_vote.decision.eq(&U256::from(1)) {
            log::debug!(
                "Vote: {}, Delegator: {} Vote: 1",
                self.delegator,
                self.voter
            );
            return Ok(VoteDecision::Yes((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(2)) {
            log::debug!(
                "Vote: {}, Delegator: {} Vote: 2",
                self.delegator,
                self.voter
            );
            return Ok(VoteDecision::No((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(3)) {
            log::debug!(
                "Vote: {}, Delegator: {} Vote: 3",
                self.delegator,
                self.voter
            );
            return Ok(VoteDecision::NoWithVeto((self.clone(), inferred_vote)));
        }

        if inferred_vote.decision.eq(&U256::from(4)) {
            log::debug!(
                "Vote: {}, Delegator: {} Vote: 4",
                self.delegator,
                self.voter
            );
            return Ok(VoteDecision::Abstain((self.clone(), inferred_vote)));
        }

        log::debug!("inferred vote decision is: {}", inferred_vote.decision);

        return Ok(VoteDecision::Invalid(self.clone()));
    }
}

fn decrypt_ecies(receiver_priv: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let result = ecies::decrypt(receiver_priv, msg).map_err(|e| anyhow!(e))?;
    Ok(result)
}

fn encrypt_ecies(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let result = ecies::encrypt(receiver_pub, msg).map_err(|e| anyhow!(e))?;
    Ok(result)
}

fn hash_eip191_message(msg: &[u8]) -> B256 {
    // EIP-191: keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut data = Vec::with_capacity(prefix.len() + msg.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(msg);
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use crate::kms::kms::{DirtyKMS, KMS};

    use super::*;
    use alloy::{
        primitives::{B256, U256},
        signers::{k256::SecretKey as KSec, local::PrivateKeySigner as SigningPrivateKey},
    };
    use anyhow::Ok;
    use dotenvy::dotenv;
    use ecies::utils::generate_keypair;
    use ecies::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionPrivateKey};

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
    async fn test_fe_generated_vote_1() -> Result<()> {
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

        let VoteDecision::Yes(inner) = inferred_vote else {
            panic!("expected Yes(..), got {inferred_vote:?}");
        };
        println!("{:?}", inner);

        Ok(())
    }

    #[tokio::test]
    async fn test_fe_generated_vote_2() -> Result<()> {
        let proposal_id =
            "0xBC156CE89605FB67D1937A1B9DB79BFD57E6246CBB89A81A9D8BBDF760B92F76".parse()?;
        let vote = GovernanceVote {
            voter: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegator: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegatorChainId: "421614".parse()?,
            voteEncrypted: "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000C104222B8F9CCDEB2CC762578FFEA2EAC00BE5A05D9446500BC6C1BCDD1E34852CC640AD869C176B5F56E6685540D78B5B1767DFEF193E8656E71DE855CE7E76AE596772851D59413D5E505621147058203B3CD6EBE472F981347E80CA7A3C7D58F508CE39DB974685A76E12272819F3EA9967D805895D7382C41F33A6960BEBF82CA600B010884DBF7BAA8F62C50D61C2B5D1EE7141228ED2F098C63F09B6D951A66AB40F8BCD4ED67D110F4B0F5AA274FBED1FA2EDBFC7031E9E733AD81922B230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041F6AFA258AEFE599E160417636A76D87929B8B74A160FD765882373F02A008A7403DC74A785ACB9D2469B56CC7C7B6A4F58E9EDFC248FE95860F3A08BC57240E41B00000000000000000000000000000000000000000000000000000000000000".parse()?,
        };

        let sk = DirtyKMS::default()
            .get_proposal_secret_key(proposal_id)
            .await?;

        let inferred_vote = vote.to_vote_decision(sk, proposal_id);

        let VoteDecision::Invalid(inner) = inferred_vote else {
            panic!("expected Invalid(..), got {inferred_vote:?}");
        };
        println!("{:?}", inner);

        Ok(())
    }

    #[tokio::test]
    async fn test_fe_generated_vote_3() -> Result<()> {
        let proposal_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse()?;
        let vote = GovernanceVote {
            voter: "0x868683A80eA3038fbcfc1Cc0C0b4078de2ECaF92".parse()?,
            delegator: "0x868683A80eA3038fbcfc1Cc0C0b4078de2ECaF92".parse()?,
            delegatorChainId: "421614".parse()?,
            voteEncrypted: "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c104806cd77303339c048871cc1e5d8cbf59e95e47ea951652d733cdb2754eb2e5319e383ff2c636876cbcc46918157fdfbffe49858886c65419973800a473fe43672fbba6516192ca81d220e113bcc1ab82f228c66af528b37c22b770ff94bb4bb5cff3f37e3718a3f49611296532c052d405250772933e487c6fa51acf1c021e8b8581e1312bcd055c7cefe5bf3ac27fa3de53ae078dfb90937032926a4759d10226d3da7b908a9c384346e4f46cb6a86b6d3dc65a7905ab023d7e9d386b9212b9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041beebc79d27f762fe0800912fb7d3c7cea65f6b42acb6f82aed53ae0ad66bc67f709fc779e7bb084889279aab75b909c2ac55f81c5b3b4c390d09551b5d89cbc41b00000000000000000000000000000000000000000000000000000000000000".parse()?,
        };

        let bytes_vec =
            hex::decode("b2d338d9a74c00d314fb2456cce8f790618281085812c29e6d247d1dde5e67d8")?;
        let sk_bytes: [u8; 32] = bytes_vec
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))?;

        let sk = EncryptionPrivateKey::parse(&sk_bytes).map_err(|e| anyhow!(e))?;

        let inferred_vote = vote.to_vote_decision(sk, proposal_id);

        let VoteDecision::No(inner) = inferred_vote else {
            panic!("expected No(..), got {inferred_vote:?}");
        };
        println!("{:?}", inner);

        Ok(())
    }

    #[tokio::test]
    async fn test_fe_generated_vote_4() -> Result<()> {
        let proposal_id =
            "81837480D55D644C4EFC82BEE8E7ECDB4DC98A30093FB92565D3C968F222E35C".parse()?;
        let vote = GovernanceVote {
            voter: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegator: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegatorChainId: "421614".parse()?,
            voteEncrypted: "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000C1045F4BFAAF893011BAAC8874705074DD39C13BB5ADFB9BE96A8CDFB370CE6F7EF507D8E3A213BB5F418F3193BDB2D20F701E73166FEAB0DD29009A9DC87A83A67972ABA51962C4163FD43AB331E12036AC41BA59E1C56D4A28F68D99979A40789D93FA9A2C794A337B58AAB706FF026CB0725151FC9A72B44BDDDEFCAA40399F913BAF75864874342B6B7A422A0AA726512374474FE7A2590A89B9CD9BD5A6C692E04128EA995B3EF9FDF516F288D8D259218B8C1321497AC10A3301204DBB58D9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041D49815CBE2F68379A9CBC4D1E2987FBAC8AEB597341AC1870CB5ED08FB9C51333C6D9F5168782CA3785A3E49BCFB150D11CD957989782E13A0E14730546300441B00000000000000000000000000000000000000000000000000000000000000".parse()?,
        };

        let sk = DirtyKMS::default()
            .get_proposal_secret_key(proposal_id)
            .await?;

        let inferred_vote = vote.to_vote_decision(sk, proposal_id);

        let VoteDecision::Invalid(inner) = inferred_vote else {
            panic!("expected Invalid(..), got {inferred_vote:?}");
        };
        println!("{:?}", inner);

        Ok(())
    }

    #[tokio::test]
    async fn test_fe_generated_vote_5() -> Result<()> {
        let proposal_id =
            "6D5758F1E70E7F111246C170B660618CF5AADE03314EB624B620BCCCB2240DCA".parse()?;
        let vote = GovernanceVote {
            voter: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegator: "0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5".parse()?,
            delegatorChainId: "421614".parse()?,
            voteEncrypted: "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000C104A9FC2E5C645796C11962C0D007250138B61469C46366BA15FC43A52431C8FB8425A86B906724E94F7E276E539503B16AC2BFD24284524915DDD563C05DFF4B15A6F16A90B6257132028177D6760D7D30DCE3166A8DD9FA70CA7E2C3858CA4AEA6DB48A315B70363EE3B862C8365EE203C3901FBB2314E54677B760C41C6C7ED061D6624C2CC506830C7C372B2452E948EC0463FCFF20E954CEE5CBE2F73E8D1FF4EC8D2C7FC9337C0E260C31D40E46828CBE9959B8745C7EA6D96E307D403EEE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411182C721C042494CFF2F32558996A820454E11B3C590A6CC680C5A223F01BE7515C8E595676F459F01B75DC532D6F87B6B8AEB06B31FDFCF1A67348EAAACC9971C00000000000000000000000000000000000000000000000000000000000000".parse()?,
        };

        let sk = DirtyKMS::default()
            .get_proposal_secret_key(proposal_id)
            .await?;

        let inferred_vote = vote.to_vote_decision(sk, proposal_id);

        let VoteDecision::Invalid(inner) = inferred_vote else {
            panic!("expected Invalid(..), got {inferred_vote:?}");
        };
        println!("{:?}", inner);

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
