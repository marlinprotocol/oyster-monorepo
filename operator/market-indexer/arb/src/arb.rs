use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::hex::ToHexExt;
use alloy::primitives::Address;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::Filter;
use alloy::rpc::types::eth::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::Url;
use alloy::transports::ws::WebSocketConfig;
use anyhow::{Context, Result};
use indexer_framework::chain::{ChainHandler, FromLog};
use indexer_framework::events::*;
use tokio::time::timeout;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tokio_stream::StreamExt;
use tracing::warn;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MarketV1Contract,
    "./abi/MarketV1min.json"
);

#[derive(Debug, Clone)]
pub struct ArbLog(pub Log);

impl FromLog for ArbLog {
    fn to_job_event(&self) -> Result<Option<JobEvent>> {
        match self.0.topic0() {
            Some(&MarketV1Contract::JobOpened::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobOpened::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobOpened event data")?
                    .data;

                Ok(Some(JobEvent::Opened(JobOpened {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    owner: decoded_data.owner.encode_hex_with_prefix(),
                    provider: decoded_data.provider.encode_hex_with_prefix(),
                    metadata: decoded_data.metadata,
                    rate: decoded_data.rate,
                    balance: decoded_data.balance,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&MarketV1Contract::JobClosed::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobClosed::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobClosed event data")?
                    .data;

                Ok(Some(JobEvent::Closed(JobClosed {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                })))
            }
            Some(&MarketV1Contract::JobSettled::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobSettled::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobSettled event data")?
                    .data;

                Ok(Some(JobEvent::Settled(JobSettled {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&MarketV1Contract::JobDeposited::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobDeposited::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobDeposited event data")?
                    .data;

                Ok(Some(JobEvent::Deposited(JobDeposited {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    from: decoded_data.from.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&MarketV1Contract::JobWithdrew::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobWithdrew::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobWithdrew event data")?
                    .data;

                Ok(Some(JobEvent::Withdrew(JobWithdrew {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    to: decoded_data.to.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&MarketV1Contract::JobReviseRateInitiated::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateInitiated::decode_log(&self.0.inner)
                        .context("Failed to ABI decode JobReviseRateInitiated event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateInitiated(
                    JobReviseRateInitiated {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&MarketV1Contract::JobReviseRateCancelled::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateCancelled::decode_log(&self.0.inner)
                        .context("Failed to ABI decode JobReviseRateCancelled event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateCancelled(
                    JobReviseRateCancelled {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                    },
                )))
            }
            Some(&MarketV1Contract::JobReviseRateFinalized::SIGNATURE_HASH) => {
                let decoded_data =
                    MarketV1Contract::JobReviseRateFinalized::decode_log(&self.0.inner)
                        .context("Failed to ABI decode JobReviseRateFinalized event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateFinalized(
                    JobReviseRateFinalized {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&MarketV1Contract::JobMetadataUpdated::SIGNATURE_HASH) => {
                let decoded_data = MarketV1Contract::JobMetadataUpdated::decode_log(&self.0.inner)
                    .context("Failed to ABI decode JobMetadataUpdated event data")?
                    .data;

                Ok(Some(JobEvent::MetadataUpdated(JobMetadataUpdated {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    new_metadata: decoded_data.metadata,
                })))
            }
            _ => Ok(None), // unknown event, skip
        }
    }
}

type WsProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

#[derive(Clone)]
pub struct ArbProvider {
    pub provider: Arc<WsProvider>,
    pub contract: Address,
}

impl ArbProvider {
    pub async fn new(rpc_url: Url, contract: Address) -> Result<Self> {
        let mut ws_config = WebSocketConfig::default();
        ws_config.max_frame_size = Some(64 << 20);

        let provider = timeout(
            Duration::from_secs(10),
            ProviderBuilder::new().connect_ws(WsConnect::new(rpc_url).with_config(ws_config)),
        )
        .await
        .context("Timed out connecting to the websocket RPC URL")?
        .context("Failed to connect to the websocket RPC URL")?;

        Ok(Self {
            provider: Arc::new(provider),
            contract,
        })
    }
}

impl ChainHandler for ArbProvider {
    type RawLog = ArbLog;

    async fn fetch_chain_id(&self) -> Result<String> {
        let provider = self.provider.clone();
        let chain_id = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .take(3)
                .map(jitter),
            || async { provider.get_chain_id().await },
        )
        .await
        .context("Failed to fetch chain ID from the RPC")?;

        Ok(chain_id.to_string())
    }

    async fn fetch_extra_decimals(&self) -> Result<i64> {
        let provider = self.provider.clone();
        let market = MarketV1Contract::new(self.contract, &provider);

        let extra_decimals = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .take(3)
                .map(jitter),
            || async { market.EXTRA_DECIMALS().call().await },
        )
        .await
        .context("Failed to fetch market EXTRA_DECIMALS from the RPC")?;

        Ok(extra_decimals.saturating_to::<i64>())
    }

    async fn fetch_latest_block(&self) -> Result<u64> {
        let provider = self.provider.clone();
        let block_number = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .take(5)
                .map(jitter),
            || async { provider.get_block_number().await },
        )
        .await
        .context("Failed to fetch latest block number from the RPC")?;

        Ok(block_number)
    }

    async fn fetch_logs_grouped_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<BTreeMap<u64, Vec<ArbLog>>> {
        let provider = self.provider.clone();
        let logs = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .take(5)
                .map(jitter),
            || async {
                provider
                    .get_logs(
                        &Filter::new()
                            .events(vec![
                                MarketV1Contract::JobOpened::SIGNATURE,
                                MarketV1Contract::JobSettled::SIGNATURE,
                                MarketV1Contract::JobClosed::SIGNATURE,
                                MarketV1Contract::JobDeposited::SIGNATURE,
                                MarketV1Contract::JobWithdrew::SIGNATURE,
                                MarketV1Contract::JobReviseRateInitiated::SIGNATURE,
                                MarketV1Contract::JobReviseRateCancelled::SIGNATURE,
                                MarketV1Contract::JobReviseRateFinalized::SIGNATURE,
                                MarketV1Contract::JobMetadataUpdated::SIGNATURE,
                            ])
                            .from_block(start_block)
                            .to_block(end_block)
                            .address(self.contract),
                    )
                    .await
                    .inspect_err(|err| {
                        warn!(
                            start_block,
                            end_block,
                            error = ?err,
                            "Retrying get_logs RPC call"
                        );
                    })
            },
        )
        .await
        .context(format!(
            "Failed to fetch logs for block range ({}, {}) from the RPC",
            start_block, end_block
        ))?;

        let mut block_logs: BTreeMap<u64, Vec<ArbLog>> = BTreeMap::new();
        for log in logs {
            if let Some(block_number) = log.block_number {
                block_logs
                    .entry(block_number)
                    .or_default()
                    .push(ArbLog(log));
            }
        }

        Ok(block_logs)
    }

    async fn subscribe_logs_grouped_by_block<'a>(
        &'a self,
    ) -> Result<impl StreamExt<Item = (u64, Vec<Self::RawLog>)> + Send + 'a> {
        let provider = self.provider.clone();

        let stream = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(10))
                .map(jitter)
                .take(5),
            || async {
                provider
                    .subscribe_logs(
                        &Filter::new()
                            .events(vec![
                                MarketV1Contract::JobOpened::SIGNATURE,
                                MarketV1Contract::JobSettled::SIGNATURE,
                                MarketV1Contract::JobClosed::SIGNATURE,
                                MarketV1Contract::JobDeposited::SIGNATURE,
                                MarketV1Contract::JobWithdrew::SIGNATURE,
                                MarketV1Contract::JobReviseRateInitiated::SIGNATURE,
                                MarketV1Contract::JobReviseRateCancelled::SIGNATURE,
                                MarketV1Contract::JobReviseRateFinalized::SIGNATURE,
                                MarketV1Contract::JobMetadataUpdated::SIGNATURE,
                            ])
                            .address(self.contract),
                    )
                    .await
                    .inspect_err(|err| {
                        warn!(
                            error = ?err,
                            "Retrying subscribe_logs RPC call"
                        );
                    })
            },
        )
        .await
        .context("Failed to subscribe to logs on chain using RPC")?
        .into_stream();

        let grouped_stream = async_stream::stream! {
            let _keep_alive = provider;

            let mut current_block: Option<u64> = None;
            let mut current_batch: Vec<ArbLog> = Vec::new();

            tokio::pin!(stream);

            while let Some(log) = stream.next().await {
                if let Some(block_number) = log.block_number {
                    match current_block {
                        Some(cur) if cur == block_number => {
                            current_batch.push(ArbLog(log));
                        }
                        Some(cur) => {
                            yield (cur, std::mem::take(&mut current_batch));
                            current_block = Some(block_number);
                            current_batch.push(ArbLog(log));
                        }
                        None => {
                            current_block = Some(block_number);
                            current_batch.push(ArbLog(log));
                        }
                    }
                }
            }

            if let Some(cur) = current_block {
                yield (cur, current_batch);
            }
        };

        Ok(grouped_stream)
    }
}
