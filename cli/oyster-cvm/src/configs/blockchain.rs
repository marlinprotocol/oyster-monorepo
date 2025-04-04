use alloy::primitives::U256;
use anchor_client::solana_client::rpc_config::RpcSendTransactionConfig;
use anchor_client::solana_sdk::commitment_config::CommitmentLevel;
use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use std::str::FromStr;
use std::u64;

// RPC URLs
const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";
const SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

// Chain IDs
const ARBITRUM_ONE_CHAIN_ID: u64 = 42161;

// Solana Transaction Config
pub const SOLANA_TRANSACTION_CONFIG: RpcSendTransactionConfig = RpcSendTransactionConfig {
    skip_preflight: false,
    preflight_commitment: Some(CommitmentLevel::Confirmed),
    max_retries: Some(3),
    encoding: None,
    min_context_slot: None,
};

// Supported blockchains
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blockchain {
    Arbitrum,
    Solana,
}

impl Blockchain {
    pub fn blockchain_from_job_id(job_id: String) -> Result<Self> {
        let job_id_numeric = U256::from_str(&job_id).context("Invalid job ID format")?;

        // Extract chain ID
        let chain_id: u64 = (job_id_numeric >> 192_u32).to::<u64>();

        match chain_id {
            ARBITRUM_ONE_CHAIN_ID => Ok(Blockchain::Arbitrum),
            _ => {
                // Check if it matches Solana's pattern
                let mask = U256::from(u64::MAX);
                if (job_id_numeric >> 64) & mask == mask {
                    Ok(Blockchain::Solana)
                } else {
                    Err(anyhow!("Unsupported job ID format: {}", job_id))
                }
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Blockchain::Arbitrum => "arbitrum",
            Blockchain::Solana => "solana",
        }
    }

    pub fn rpc_url(&self) -> &'static str {
        match self {
            Blockchain::Arbitrum => ARBITRUM_ONE_RPC_URL,
            Blockchain::Solana => SOLANA_RPC_URL,
        }
    }
}

impl ValueEnum for Blockchain {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Arbitrum, Self::Solana]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.as_str().into())
    }
}
