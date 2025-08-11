use ethers::abi::{Token, encode};
use ethers::types::{H256, U256};
use k256::sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::types::VoteOutcome;

pub fn compute_result_hash(
    gov_contract_addr: ethers::types::Address,
    start_ts: U256,
    network_hash: H256,
    vote_hash: H256,
) -> H256 {
    let tokens = vec![
        Token::Address(gov_contract_addr),
        Token::Uint(start_ts),
        Token::FixedBytes(network_hash.as_bytes().to_vec()),
        Token::FixedBytes(vote_hash.as_bytes().to_vec()),
    ];

    let encoded = encode(&tokens);
    let result = Sha256::digest(&encoded);
    H256::from_slice(&result)
}

pub fn serialize_vote_result(results: &HashMap<VoteOutcome, U256>, supply: U256) -> Vec<Token> {
    let yes = results.get(&VoteOutcome::Yes).cloned().unwrap_or_default();
    let no = results.get(&VoteOutcome::No).cloned().unwrap_or_default();
    let abstain = results
        .get(&VoteOutcome::Abstain)
        .cloned()
        .unwrap_or_default();
    let no_with_veto = results
        .get(&VoteOutcome::NoWithVeto)
        .cloned()
        .unwrap_or_default();

    vec![
        Token::Uint(yes),
        Token::Uint(no),
        Token::Uint(abstain),
        Token::Uint(no_with_veto),
        Token::Uint(supply),
    ]
}

pub fn compute_vote_result_hash(
    contract_data_hash: [u8; 32],
    proposal_id: [u8; 32],
    vote_result: Vec<Token>,
) -> H256 {
    let mut all_tokens = vec![
        Token::FixedBytes(contract_data_hash.to_vec()),
        Token::FixedBytes(proposal_id.to_vec()),
    ];

    all_tokens.extend(vote_result);

    let encoded = encode(&all_tokens);
    let digest = Sha256::digest(&encoded);
    H256::from_slice(&digest)
}

pub fn compute_chain_hash(chain_id: u64, rpc_urls: &[String]) -> [u8; 32] {
    let encoded = encode(&[
        Token::Uint(chain_id.into()),
        Token::Array(
            rpc_urls
                .iter()
                .map(|url| Token::String(url.clone()))
                .collect(),
        ),
    ]);

    Sha256::digest(&encoded).into()
}

pub fn compute_network_hash(chain_hashes: Vec<[u8; 32]>) -> [u8; 32] {
    let mut encoded: Vec<u8> = vec![];

    for chain_hash in chain_hashes {
        encoded = encode(&[
            Token::Bytes(encoded.clone()),
            Token::FixedBytes(chain_hash.to_vec()),
        ]);
    }

    Sha256::digest(&encoded).into()
}

pub fn update_vote_hash(current_hash: [u8; 32], encrypted: &[u8]) -> [u8; 32] {
    let vote_encrypted_hash = Sha256::digest(encrypted);
    let mut hasher = Sha256::new();
    hasher.update(&current_hash);
    hasher.update(&vote_encrypted_hash);
    hasher.finalize().into()
}
