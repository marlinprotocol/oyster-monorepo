use std::str::FromStr;

use alloy::{
    hex::ToHexExt,
    network::EthereumWallet,
    primitives::{Address, FixedBytes, U256, keccak256},
    providers::{
        Provider, ProviderBuilder, RootProvider, WalletProvider,
        fillers::{
            ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, SimpleNonceManager,
            WalletFiller,
        },
    },
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tracing::info;

use crate::deployment::adapter::{
    ChainFunds, ChainProvider, ChainTransaction, JobData, JobTransactionKind,
};

use super::adapter::DeploymentAdapter;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/token_abi.json"
);

pub type EvmProvider = FillProvider<
    JoinFill<
        JoinFill<
            JoinFill<
                JoinFill<alloy::providers::Identity, GasFiller>,
                NonceFiller<SimpleNonceManager>,
            >,
            ChainIdFiller,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

pub struct EvmAdapter {
    pub rpc_url: String,
    pub market_address: String,
    pub usdc_address: String,
    pub sender_address: Option<Address>,
}

#[async_trait]
impl DeploymentAdapter for EvmAdapter {
    async fn create_provider_with_wallet(
        &mut self,
        wallet_private_key: &str,
    ) -> Result<ChainProvider> {
        let private_key = FixedBytes::<32>::from_slice(
            &hex::decode(wallet_private_key).context("Failed to decode private key")?,
        );

        let signer = PrivateKeySigner::from_bytes(&private_key)
            .context("Failed to create signer from private key")?;
        self.sender_address = Some(signer.address());

        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::default()
            .with_gas_estimation()
            .with_simple_nonce_management()
            .fetch_chain_id()
            .wallet(wallet)
            .connect_http(self.rpc_url.parse().context("Failed to parse RPC URL")?);

        Ok(ChainProvider::Evm(provider))
    }

    async fn get_operator_cp(&self, operator: &str, provider: &ChainProvider) -> Result<String> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let market_address = Address::from_str(&self.market_address)?;
        let operator_address = Address::from_str(operator)?;

        // Create contract instance
        let market = OysterMarket::new(market_address, provider);

        // Call providers function to get CP URL
        let cp_url = market.providers(operator_address).call().await?;

        Ok(cp_url)
    }

    async fn fetch_extra_decimals(&self, provider: &ChainProvider) -> Result<i64> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let market_address = Address::from_str(&self.market_address)?;

        // Create contract instance
        let market = OysterMarket::new(market_address, provider);

        // Call providers function to get CP URL
        let extra_decimals = market.EXTRA_DECIMALS().call().await?;

        Ok(extra_decimals.saturating_to::<i64>())
    }

    async fn get_job_data_if_exists(
        &self,
        job_id: String,
        provider: &ChainProvider,
    ) -> Result<Option<JobData>> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let market_address = Address::from_str(&self.market_address)?;

        // Create contract instance
        let market = OysterMarket::new(market_address, provider);

        // Check if job exists
        let job = market
            .jobs(job_id.parse().context("Failed to parse job ID")?)
            .call()
            .await
            .context("Failed to fetch job details")?;

        if job.owner == Address::ZERO {
            return Ok(None);
        }

        Ok(Some(JobData {
            metadata: job.metadata,
            balance: job.balance,
            rate: job.rate,
            last_settled: job.lastSettled.saturating_to::<i64>(),
        }))
    }

    async fn prepare_funds(
        &self,
        amount_usdc: U256,
        provider: &ChainProvider,
    ) -> Result<ChainFunds> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let usdc_address: Address = self
            .usdc_address
            .parse()
            .context("Failed to parse USDC address")?;
        let market_address: Address = self
            .market_address
            .parse()
            .context("Failed to parse market address")?;
        let signer_address = provider
            .signer_addresses()
            .next()
            .ok_or_else(|| anyhow!("No signer address found"))?;
        let usdc = USDC::new(usdc_address, provider);

        // Get the current allowance
        let current_allowance = usdc
            .allowance(signer_address, market_address)
            .call()
            .await
            .context("Failed to get current USDC allowance")?;

        // Only approve if the current allowance is less than the required amount
        if current_allowance < amount_usdc {
            info!(
                "Current allowance ({}) is less than required amount ({}), approving USDC transfer...",
                current_allowance, amount_usdc
            );
            let tx_hash = usdc
                .approve(market_address, amount_usdc)
                .send()
                .await
                .context("Failed to send USDC approval transaction")?
                .watch()
                .await
                .context("Failed to get USDC approval transaction hash")?;

            info!("USDC approval transaction: {:?}", tx_hash);
        } else {
            info!(
                "Current allowance ({}) is sufficient for the required amount ({}), skipping approval",
                current_allowance, amount_usdc
            );
        }
        Ok(ChainFunds::Evm(()))
    }

    async fn send_transaction(
        &self,
        is_create_job: bool,
        transaction: ChainTransaction,
        provider: &ChainProvider,
    ) -> Result<Option<String>> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let ChainTransaction::Evm(transaction) = transaction else {
            return Err(anyhow!("Internal error"));
        };

        // Create job_open call
        let tx_hash = provider
            .send_transaction(*transaction.clone())
            .await?
            .watch()
            .await?;
        info!("Transaction hash: {:?}", tx_hash);

        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

        // Add logging to check transaction status
        if !receipt.status() {
            return Err(anyhow!("Transaction failed - check contract interaction"));
        }

        if is_create_job {
            // Calculate event signature hash
            let job_opened_signature =
                "JobOpened(bytes32,string,address,address,uint256,uint256,uint256)";
            let job_opened_topic = keccak256(job_opened_signature.as_bytes());

            // Look for JobOpened event
            for log in receipt.inner.logs().iter() {
                if log.topics()[0] == job_opened_topic {
                    info!("Found JobOpened event");
                    return Ok(Some(log.topics()[1].0.encode_hex_with_prefix()));
                }
            }

            // If we can't find the JobOpened event
            info!("No JobOpened event found. All topics:");
            for log in receipt.inner.logs().iter() {
                info!("Event topics: {:?}", log.topics());
            }

            return Err(anyhow!(
                "Could not find JobOpened event in transaction receipt"
            ));
        }

        Ok(None)
    }

    async fn create_job_transaction(
        &self,
        kind: JobTransactionKind,
        _fund: Option<ChainFunds>,
        provider: &ChainProvider,
    ) -> Result<ChainTransaction> {
        let ChainProvider::Evm(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let market_address = self.market_address.parse::<Address>()?;

        // Load OysterMarket contract using Alloy
        let market = OysterMarket::new(market_address, provider);

        Ok(ChainTransaction::Evm(Box::new(match kind {
            JobTransactionKind::Create {
                metadata,
                operator,
                rate,
                balance,
            } => market
                .jobOpen(metadata, operator.parse::<Address>()?, rate, balance)
                .into_transaction_request(),
            JobTransactionKind::Deposit { job_id, amount } => market
                .jobDeposit(job_id.parse().context("Failed to parse job ID")?, amount)
                .into_transaction_request(),
            JobTransactionKind::ReviseRateInitiate { job_id, rate } => market
                .jobReviseRateInitiate(job_id.parse().context("Failed to parse job ID")?, rate)
                .into_transaction_request(),
            JobTransactionKind::Close { job_id } => market
                .jobClose(job_id.parse().context("Failed to parse job ID")?)
                .into_transaction_request(),
            JobTransactionKind::Update { job_id, metadata } => market
                .jobMetadataUpdate(job_id.parse().context("Failed to parse job ID")?, metadata)
                .into_transaction_request(),
            JobTransactionKind::Withdraw { job_id, amount } => market
                .jobWithdraw(job_id.parse().context("Failed to parse job ID")?, amount)
                .into_transaction_request(),
        })))
    }

    fn get_sender_address(&self) -> String {
        self.sender_address
            .map(|addr| addr.to_string())
            .unwrap_or_default()
    }
}
