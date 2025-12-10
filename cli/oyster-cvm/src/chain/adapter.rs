use alloy::{primitives::U256, rpc::types::TransactionRequest};
use anyhow::Result;
use async_trait::async_trait;
use sui_sdk_types::{ObjectReference, Transaction};

use crate::chain::{evm::EvmProvider, sui::SuiProvider};

#[derive(Clone)]
pub enum ChainProvider {
    Evm(EvmProvider),
    Sui(Box<SuiProvider>),
}

#[derive(Debug, Clone)]
pub enum ChainTransaction {
    Evm(Box<TransactionRequest>),
    Sui(Box<Transaction>),
}

#[derive(Debug, Clone)]
pub enum ChainFunds {
    Evm(()),
    Sui(ObjectReference),
}

#[derive(Debug, Clone)]
pub struct JobData {
    pub metadata: String,
    pub balance: U256,
    pub rate: U256,
    pub last_settled: i64,
}

#[derive(Debug, Clone)]
pub enum JobTransactionKind {
    Create {
        metadata: String,
        operator: String,
        rate: U256,
        balance: U256,
    },
    Deposit {
        job_id: String,
        amount: U256,
    },
    ReviseRateInitiate {
        job_id: String,
        rate: U256,
    },
    Close {
        job_id: String,
    },
    Update {
        job_id: String,
        metadata: String,
    },
    Withdraw {
        job_id: String,
        amount: U256,
    },
}

#[async_trait]
pub trait DeploymentAdapter: Send + Sync {
    async fn create_provider_with_wallet(
        &mut self,
        wallet_private_key: &str,
    ) -> Result<ChainProvider>;

    async fn get_operator_cp(&self, operator: &str, provider: &ChainProvider) -> Result<String>;
    async fn fetch_extra_decimals(&self, provider: &ChainProvider) -> Result<i64>;
    async fn get_job_data_if_exists(
        &self,
        job_id: String,
        provider: &ChainProvider,
    ) -> Result<Option<JobData>>;

    async fn prepare_funds(
        &self,
        amount_usdc: U256,
        provider: &ChainProvider,
    ) -> Result<ChainFunds>;
    async fn create_job_transaction(
        &self,
        kind: JobTransactionKind,
        fund: Option<ChainFunds>,
        provider: &ChainProvider,
    ) -> Result<ChainTransaction>;
    async fn send_transaction(
        &self,
        is_create_job: bool,
        transaction: ChainTransaction,
        provider: &ChainProvider,
    ) -> Result<Option<String>>;

    fn get_sender_address(&self) -> String;
}
