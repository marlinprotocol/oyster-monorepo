use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use anyhow::{Context, Result, anyhow};
use indexer_framework::SaturatingConvert;
use indexer_framework::chain::{ChainHandler, FromLog};
use indexer_framework::events::{self, JobEvent};
use serde::Deserialize;
use sui_rpc::client::Client;
use sui_rpc::client::HeadersInterceptor;
use sui_rpc::field::FieldMask;
use sui_rpc::proto::sui::rpc::v2::{
    Checkpoint, Command, GetCheckpointRequest, GetServiceInfoRequest, MoveCall,
    ProgrammableTransaction, SimulateTransactionRequest, Transaction, TransactionKind,
};
use sui_sdk_types::{Address, CheckpointData};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::{debug, warn};

const GRPC_AUTH_TOKEN: &str = "x-token";

const DEFAULT_FETCH_CONCURRENCY: usize = 64;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const MODULE_NAME: &str = "market";
const EXTRA_DECIMALS_FUNCTION_NAME: &str = "extra_decimals";

/// Sui oyster market program events
#[derive(Debug, Deserialize)]
struct JobOpened {
    job_id: u128,
    owner: Address,
    provider: Address,
    metadata: String,
    rate: u64,
    balance: u64,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct JobClosed {
    job_id: u128,
}

#[derive(Debug, Deserialize)]
struct JobDeposited {
    job_id: u128,
    from: Address,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct JobSettled {
    job_id: u128,
    amount: u64,
    settled_until: u64,
}

#[derive(Debug, Deserialize)]
struct JobMetadataUpdated {
    job_id: u128,
    new_metadata: String,
}

#[derive(Debug, Deserialize)]
struct JobWithdrew {
    job_id: u128,
    to: Address,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateInitiated {
    job_id: u128,
    new_rate: u64,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateCancelled {
    job_id: u128,
}

#[derive(Debug, Deserialize)]
struct JobReviseRateFinalized {
    job_id: u128,
    new_rate: u64,
}

#[derive(Debug)]
pub struct SuiLog {
    pub type_: String,
    pub contents: Vec<u8>,
}

impl FromLog for SuiLog {
    fn to_job_event(&self) -> Result<Option<JobEvent>> {
        let Some(event_name) = self.type_.split("::").last() else {
            // Invalid event type, skip
            return Ok(None);
        };

        match event_name {
            "JobOpened" => {
                let decoded_data: JobOpened = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobOpened event data")?;

                Ok(Some(JobEvent::Opened(events::JobOpened {
                    job_id: decoded_data.job_id.to_string(),
                    owner: decoded_data.owner.to_string(),
                    provider: decoded_data.provider.to_string(),
                    metadata: decoded_data.metadata,
                    rate: U256::from(decoded_data.rate),
                    balance: U256::from(decoded_data.balance),
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            "JobClosed" => {
                let decoded_data: JobClosed = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobClosed event data")?;

                Ok(Some(JobEvent::Closed(events::JobClosed {
                    job_id: decoded_data.job_id.to_string(),
                })))
            }
            "JobDeposited" => {
                let decoded_data: JobDeposited = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobDeposited event data")?;

                Ok(Some(JobEvent::Deposited(events::JobDeposited {
                    job_id: decoded_data.job_id.to_string(),
                    from: decoded_data.from.to_string(),
                    amount: U256::from(decoded_data.amount),
                })))
            }
            "JobSettled" => {
                let decoded_data: JobSettled = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobSettled event data")?;

                Ok(Some(JobEvent::Settled(events::JobSettled {
                    job_id: decoded_data.job_id.to_string(),
                    amount: U256::from(decoded_data.amount),
                    timestamp: decoded_data.settled_until.saturating_to(),
                })))
            }
            "JobMetadataUpdated" => {
                let decoded_data: JobMetadataUpdated = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobMetadataUpdated event data")?;

                Ok(Some(JobEvent::MetadataUpdated(
                    events::JobMetadataUpdated {
                        job_id: decoded_data.job_id.to_string(),
                        new_metadata: decoded_data.new_metadata,
                    },
                )))
            }
            "JobWithdrew" => {
                let decoded_data: JobWithdrew = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobWithdrew event data")?;

                Ok(Some(JobEvent::Withdrew(events::JobWithdrew {
                    job_id: decoded_data.job_id.to_string(),
                    to: decoded_data.to.to_string(),
                    amount: U256::from(decoded_data.amount),
                })))
            }
            "JobReviseRateInitiated" => {
                let decoded_data: JobReviseRateInitiated = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobReviseRateInitiated event data")?;

                Ok(Some(JobEvent::ReviseRateInitiated(
                    events::JobReviseRateInitiated {
                        job_id: decoded_data.job_id.to_string(),
                        new_rate: U256::from(decoded_data.new_rate),
                    },
                )))
            }
            "JobReviseRateCancelled" => {
                let decoded_data: JobReviseRateCancelled = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobReviseRateCancelled event data")?;

                Ok(Some(JobEvent::ReviseRateCancelled(
                    events::JobReviseRateCancelled {
                        job_id: decoded_data.job_id.to_string(),
                    },
                )))
            }
            "JobReviseRateFinalized" => {
                let decoded_data: JobReviseRateFinalized = bcs::from_bytes(&self.contents)
                    .context("Failed to bcs decode JobReviseRateFinalized event data")?;

                Ok(Some(JobEvent::ReviseRateFinalized(
                    events::JobReviseRateFinalized {
                        job_id: decoded_data.job_id.to_string(),
                        new_rate: U256::from(decoded_data.new_rate),
                    },
                )))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct SuiProvider {
    pub grpc_client: Client,
    pub remote_client: Arc<reqwest::Client>,
    pub remote_checkpoint_url: String,
    pub package_id: String,
}

impl SuiProvider {
    pub fn new(
        grpc_url: String,
        rpc_username: Option<String>,
        rpc_password: Option<String>,
        rpc_token: Option<String>,
        remote_checkpoint_url: String,
        package_id: String,
    ) -> Result<Self> {
        let mut client = Client::new(&grpc_url)
            .context("Failed to initialize gRPC client from the provided url")?;

        if let Some(username) = rpc_username {
            let mut headers = HeadersInterceptor::default();
            headers.basic_auth(username, rpc_password);
            client = client.with_headers(headers);
        } else if let Some(token) = rpc_token {
            let mut headers = HeadersInterceptor::default();
            headers.headers_mut().insert(
                GRPC_AUTH_TOKEN,
                token
                    .parse()
                    .context("Failed to parse the auth token provided")?,
            );
            client = client.with_headers(headers);
        }

        let remote_client = Arc::new(
            reqwest::Client::builder()
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .build()
                .context("Failed to initialize reqwest client for remote call")?,
        );

        Ok(Self {
            grpc_client: client,
            remote_client,
            remote_checkpoint_url,
            package_id,
        })
    }
}

impl ChainHandler for SuiProvider {
    type RawLog = SuiLog;

    async fn fetch_chain_id(&self) -> Result<String> {
        let provider = self.grpc_client.clone();
        let service_info = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(5))
                .take(3)
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                async move {
                    timeout(
                        DEFAULT_GRPC_REQUEST_TIMEOUT,
                        provider
                            .ledger_client()
                            .get_service_info(GetServiceInfoRequest::default()),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching chain ID from the RPC")?
        .context("Request failed for fetching chain ID from the RPC")?
        .into_inner();

        service_info
            .chain_id
            .ok_or(anyhow!("RPC returned empty chain ID"))
    }

    async fn fetch_extra_decimals(&self) -> Result<i64> {
        let provider = self.grpc_client.clone();
        let move_call = MoveCall::const_default()
            .with_package(self.package_id.clone())
            .with_module(MODULE_NAME.to_string())
            .with_function(EXTRA_DECIMALS_FUNCTION_NAME.to_string());
        let transaction_kind = TransactionKind::const_default().with_programmable_transaction(
            ProgrammableTransaction::const_default()
                .with_commands(vec![Command::default().with_move_call(move_call)]),
        );

        let response = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(5))
                .take(3)
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                let request = SimulateTransactionRequest::default().with_transaction(
                    Transaction::default()
                        .with_kind(transaction_kind.clone())
                        .with_sender(Address::ZERO),
                );
                async move {
                    timeout(
                        DEFAULT_GRPC_REQUEST_TIMEOUT,
                        provider.execution_client().simulate_transaction(request),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching EXTRA_DECIMALS from the RPC")?
        .context("Request failed for fetching EXTRA_DECIMALS from the RPC")?
        .into_inner();

        if response.command_outputs.is_empty() {
            return Err(anyhow!(
                "EXTRA_DECIMALS value not found in the RPC response"
            ));
        }

        let return_values = &response.command_outputs[0].return_values;

        if return_values.is_empty() {
            return Err(anyhow!(
                "EXTRA_DECIMALS value not found in the RPC response"
            ));
        }

        Ok(bcs::from_bytes::<u8>(return_values[0].value().value())
            .context("Failed to parse EXTRA_DECIMALS value from the RPC response")?
            as i64)
    }

    async fn fetch_latest_block(&self) -> Result<u64> {
        let provider = self.grpc_client.clone();
        let current_checkpoint = Retry::spawn(
            ExponentialBackoff::from_millis(500)
                .max_delay(Duration::from_secs(5))
                .take(3)
                .map(jitter),
            move || {
                let mut provider = provider.clone();
                async move {
                    timeout(
                        DEFAULT_GRPC_REQUEST_TIMEOUT,
                        provider
                            .ledger_client()
                            .get_checkpoint(GetCheckpointRequest::latest()),
                    )
                    .await
                }
            },
        )
        .await
        .context("Request timed out for fetching latest checkpoint from the RPC")?
        .context("Request failed for fetching latest checkpoint from the RPC")?;

        Ok(current_checkpoint
            .into_inner()
            .checkpoint()
            .sequence_number())
    }

    async fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<BTreeMap<u64, Vec<Self::RawLog>>> {
        let provider = self.grpc_client.clone();
        let semaphore = Arc::new(Semaphore::new(DEFAULT_FETCH_CONCURRENCY));
        let mut set: JoinSet<Result<(u64, Vec<SuiLog>)>> = JoinSet::new();

        for seq_num in start_block..=end_block {
            let remote_client = self.remote_client.clone();
            let remote_checkpoint_url = self.remote_checkpoint_url.clone();
            let client = provider.clone();
            let package_id = self.package_id.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            set.spawn(async move {
                let _permit = permit;

                match Retry::spawn(
                    ExponentialBackoff::from_millis(500)
                        .max_delay(Duration::from_secs(5))
                        .take(3)
                        .map(jitter),
                        move || {
                            let mut client = client.clone();
                    async move {
                        timeout(DEFAULT_GRPC_REQUEST_TIMEOUT, client
                            .ledger_client()
                            .get_checkpoint(GetCheckpointRequest::by_sequence_number(seq_num)
                                .with_read_mask(FieldMask {
                                    paths: vec!["transactions".into()]
                                })
                            )
                        ).await
                    }
                },
                )
                .await
                {
                    Ok(Ok(checkpoint)) => Ok((seq_num, checkpoint_to_sui_logs(&package_id, checkpoint
                        .into_inner()
                        .checkpoint()
                        .clone()))),
                    _ => {
                        warn!(seq_num, "gRPC checkpoint fetch failed, falling back to remote checkpoint storage");

                        let checkpoint_url =
                                    format!("{}/{}.chk", remote_checkpoint_url.trim_end_matches('/'), seq_num);

                        let checkpoint = Retry::spawn(
                            ExponentialBackoff::from_millis(1000)
                                .max_delay(Duration::from_secs(10))
                                .take(3)
                                .map(jitter),
                            || async {
                                let response = remote_client.get(&checkpoint_url).send().await.context(format!("Failed to send checkpoint data request for sequence {} using remote url", seq_num))?;
                                if response.status().is_success() {
                                    Ok(response.bytes().await.context(format!("Failed to get response bytes for checkpoint data at sequence {} from remote call", seq_num))?)
                                } else {
                                    Err(anyhow!(
                                        "Remote checkpoint call for sequence {} failed with status: {}",
                                        seq_num, response.status()
                                    ))
                                }
                            },
                        )
                        .await
                        .context(format!("Failed to get checkpoint data for sequence {} using remote url", seq_num))?;

                        debug!(seq_num, bytes = checkpoint.len(), "Fetched checkpoint from remote storage");
                        Ok((seq_num, checkpoint_data_to_sui_logs(&package_id, checkpoint_data_from_bytes(&checkpoint).context(format!("Failed to deserialize checkpoint data bytes for sequence {} obtained from remote storage", seq_num))?)))
                    }
                }
            });
        }

        let mut block_logs: BTreeMap<u64, Vec<SuiLog>> = BTreeMap::new();
        while let Some(res) = set.join_next().await {
            let result = res
                .context("Failed to join task for fetching checkpoint data")?
                .context("Failed to fetch checkpoint data using gRPC and remote storage")?;
            block_logs.insert(result.0, result.1);
        }

        Ok(block_logs)
    }
}

fn checkpoint_to_sui_logs(package_id: &str, checkpoint: Checkpoint) -> Vec<SuiLog> {
    let mut logs = Vec::new();

    for tx in checkpoint.transactions {
        let Some(events) = tx.events else {
            continue;
        };

        for event in events.events {
            if !event.package_id().eq_ignore_ascii_case(package_id) {
                continue;
            }

            logs.push(SuiLog {
                type_: event.event_type().to_owned(),
                contents: event.contents().value().to_owned(),
            });
        }
    }

    logs
}

fn checkpoint_data_from_bytes(bytes: &[u8]) -> Result<CheckpointData> {
    let (encoding, data) = bytes.split_first().ok_or(anyhow!("empty bytes"))?;
    if *encoding != 1 {
        return Err(anyhow!("Invalid encoding of checkpoint bytes"));
    }

    Ok(bcs::from_bytes(data)?)
}

fn checkpoint_data_to_sui_logs(package_id: &str, checkpoint: CheckpointData) -> Vec<SuiLog> {
    let mut logs = Vec::new();

    for tx in checkpoint.transactions {
        let Some(events) = tx.events else {
            continue;
        };

        for event in events.0 {
            if !event.package_id.to_hex().eq_ignore_ascii_case(package_id) {
                continue;
            }

            logs.push(SuiLog {
                type_: event.type_.to_string(),
                contents: event.contents,
            });
        }
    }

    logs
}
