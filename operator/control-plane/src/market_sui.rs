use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use alloy::primitives::U256;
use anyhow::{anyhow, Context, Result};
use prost_types::FieldMask;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::BigDecimal;
use sqlx::{FromRow, PgPool, Postgres};
use sui_sdk::types::base_types::SuiAddress;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
use tracing::{error, info, info_span, Instrument};

use crate::utils::{
    GBRateCard, InfraProvider, JobEvent, JobId, JobResult, JobState, RealSystemContext,
    RegionalRates, SystemContext,
};

pub mod sui {
    pub mod rpc {
        pub mod v2beta2 {
            tonic::include_proto!("sui.rpc.v2beta2");
        }
    }
}

pub mod google {
    pub mod rpc {
        tonic::include_proto!("google.rpc");
    }
}

use crate::market_sui::sui::rpc::v2beta2::get_checkpoint_request::CheckpointId;
use crate::market_sui::sui::rpc::v2beta2::ledger_service_client::LedgerServiceClient;
use crate::market_sui::sui::rpc::v2beta2::subscription_service_client::SubscriptionServiceClient;
use crate::market_sui::sui::rpc::v2beta2::{
    Checkpoint, GetCheckpointRequest, SubscribeCheckpointsRequest, SubscribeCheckpointsResponse,
};

#[derive(Debug, Deserialize)]
struct JobOpened {
    job_id: u128,
    owner: SuiAddress,
    provider: SuiAddress,
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
    from: SuiAddress,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct JobSettled {
    job_id: u128,
    amount: u64,
    settled_until_ms: u64,
}

#[derive(Debug, Deserialize)]
struct JobMetadataUpdated {
    job_id: u128,
    new_metadata: String,
}

#[derive(Debug, Deserialize)]
struct JobWithdrew {
    job_id: u128,
    to: SuiAddress,
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

fn parse_log(type_: String, contents: Vec<u8>) -> Result<Option<(String, JobEvent)>> {
    let Some(event_name) = type_.split("::").last() else {
        // Invalid event type, skip
        return Ok(None);
    };

    match event_name {
        "JobOpened" => {
            let event = bcs::from_bytes::<JobOpened>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::Opened {
                    job_id: event.job_id.to_string(),
                    owner: event.owner.to_string(),
                    provider: event.provider.to_string(),
                    metadata: event.metadata,
                    rate: U256::from(event.rate),
                    balance: U256::from(event.balance),
                    timestamp: U256::from(event.timestamp),
                },
            )));
        }
        "JobClosed" => {
            let event = bcs::from_bytes::<JobClosed>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::Closed {
                    job_id: event.job_id.to_string(),
                },
            )));
        }
        "JobDeposited" => {
            let event = bcs::from_bytes::<JobDeposited>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::Deposited {
                    job_id: event.job_id.to_string(),
                    from: event.from.to_string(),
                    amount: U256::from(event.amount),
                },
            )));
        }
        "JobSettled" => {
            let event = bcs::from_bytes::<JobSettled>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::Settled {
                    job_id: event.job_id.to_string(),
                    amount: U256::from(event.amount),
                    settled_until_ms: U256::from(event.settled_until_ms),
                },
            )));
        }
        "JobMetadataUpdated" => {
            let event = bcs::from_bytes::<JobMetadataUpdated>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::MetadataUpdated {
                    job_id: event.job_id.to_string(),
                    metadata: event.new_metadata,
                },
            )));
        }
        "JobWithdrew" => {
            let event = bcs::from_bytes::<JobWithdrew>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::Withdrew {
                    job_id: event.job_id.to_string(),
                    to: event.to.to_string(),
                    amount: U256::from(event.amount),
                },
            )));
        }
        "JobReviseRateInitiated" => {
            let event = bcs::from_bytes::<JobReviseRateInitiated>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::ReviseRateInitiated {
                    job_id: event.job_id.to_string(),
                    new_rate: U256::from(event.new_rate),
                },
            )));
        }
        "JobReviseRateCancelled" => {
            let event = bcs::from_bytes::<JobReviseRateCancelled>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::ReviseRateCancelled {
                    job_id: event.job_id.to_string(),
                },
            )));
        }
        "JobReviseRateFinalized" => {
            let event = bcs::from_bytes::<JobReviseRateFinalized>(&contents)?;

            return Ok(Some((
                event.job_id.to_string(),
                JobEvent::ReviseRateFinalized {
                    job_id: event.job_id.to_string(),
                    new_rate: U256::from(event.new_rate),
                },
            )));
        }
        _ => return Ok(None),
    }
}

pub async fn run(
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    rpc: Endpoint,
    db_url: String,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    job_id: JobId,
    job_registry: JobRegistry,
) {
    let mut backoff = 1;

    let mut checkpoint_seq: i64 = 0;
    loop {
        info!("Connecting to gRPC endpoint...");
        let client = match rpc.connect().await {
            Ok(client) => {
                backoff = 1;
                info!("Connected to gRPC endpoint");
                client
            }
            Err(err) => {
                // exponential backoff on connection errors
                error!(?err, "Connection error");
                sleep(Duration::from_secs(backoff)).await;
                backoff *= 2;
                if backoff > 128 {
                    backoff = 128;
                }
                continue;
            }
        };

        // register checkpoint subscription
        let mut subscription_client = SubscriptionServiceClient::new(client.clone());
        let stream = match subscription_client
            .subscribe_checkpoints(Request::new(SubscribeCheckpointsRequest {
                read_mask: Some(FieldMask {
                    paths: vec!["sequence_number".into(), "transactions".into()],
                }),
            }))
            .await
            .context("failed to subscribe to new jobs")
        {
            Ok(stream) => stream.into_inner(),
            Err(err) => {
                error!(?err, "Subscribe error");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let mut ledger_client = LedgerServiceClient::new(client.clone());
        // get current checkpoint sequence number
        let current = match ledger_client
            .get_checkpoint(Request::new(GetCheckpointRequest {
                checkpoint_id: None,
                read_mask: None,
            }))
            .await
            .context("failed to get cutoff checkpoint sequence number")
        {
            Ok(curr) => curr.into_inner(),
            Err(err) => {
                error!(?err, "RPC error");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let Some(current) = current.checkpoint else {
            error!("Failed to get the current checkpoint");
            sleep(Duration::from_secs(1)).await;
            continue;
        };
        let current_seq = current.sequence_number() as i64;

        let db_pool = match PgPoolOptions::new()
            .connect(&db_url)
            .await
            .context("failed to connect to the provided db url")
        {
            Ok(pool) => pool,
            Err(err) => {
                error!(?err, "DB error");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let job_stream = std::pin::pin!(stream);
        checkpoint_seq = run_once(
            job_stream,
            infra_provider.clone(),
            checkpoint_seq,
            current_seq,
            ledger_client,
            db_pool,
            regions,
            rates,
            gb_rates,
            address_whitelist,
            address_blacklist,
            job_id.clone(),
            job_registry.clone(),
        )
        .await;
    }
}

async fn run_once(
    mut job_stream: impl StreamExt<Item = Result<SubscribeCheckpointsResponse, Status>> + Unpin,
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    checkpoint_seq: i64,
    current_seq: i64,
    ledger_client: LedgerServiceClient<Channel>,
    db_pool: PgPool,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    job_id: JobId,
    job_registry: JobRegistry,
) -> i64 {
    let current_checkpoint = Arc::new(Mutex::new(checkpoint_seq));

    let retry_result = Retry::spawn(
        ExponentialBackoff::from_millis(100)
            .max_delay(std::time::Duration::from_secs(5))
            .map(jitter),
        || {
            let db_pool = db_pool.clone();
            let job_id = job_id.clone();
            let job_registry = job_registry.clone();
            let infra_provider = infra_provider.clone();
            let checkpoint = current_checkpoint.clone();

            async move {
                let mut checkpoint_guard = checkpoint.lock().unwrap();
                // Begin a transaction to ensure all database operations are atomic
                let mut tx = db_pool.begin().await.map_err(|err| {
                    error!(?err, "DB error");
                    err
                })?;

                // Find all relevant job_ids for the provider's 'JobOpened' events
                let job_ids: Vec<BigDecimal> = sqlx::query_scalar(
                    r#"
        SELECT DISTINCT job_id
        FROM sui_market_events
        WHERE provider = $1
          AND event_type = 'JobOpened'
        "#,
                )
                .bind(&job_id.operator)
                .fetch_all(&mut *tx)
                .await
                .map_err(|err| {
                    error!(?err, "DB error");
                    err
                })?;

                if job_ids.is_empty() {
                    *checkpoint_guard = current_seq;
                } else {
                    // Create a temporary table and insert the job_ids
                    sqlx::query(
                        r#"
        CREATE TEMP TABLE temp_job_ids (
            job_id NUMERIC(40, 0) PRIMARY KEY
        ) ON COMMIT DROP;
        "#,
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(|err| {
                        error!(?err, "DB error");
                        err
                    })?;

                    sqlx::query(
                        r#"
        INSERT INTO temp_job_ids (job_id)
        SELECT * FROM UNNEST($1::NUMERIC(40,0)[]);
    "#,
                    )
                    .bind(&job_ids)
                    .execute(&mut *tx)
                    .await
                    .map_err(|err| {
                        error!(?err, "DB error");
                        err
                    })?;

                    {
                        // Stream and process the events
                        let mut events_stream = sqlx::query_as::<Postgres, MinimalEventDetails>(
                            r#"
            SELECT
                T1.checkpoint_sequence_number,
                T1.event_type,
                T1.bcs
            FROM sui_market_events T1
            JOIN temp_job_ids T2 ON T1.job_id = T2.job_id
            WHERE T1.checkpoint_sequence_number BETWEEN $1 AND $2
            ORDER BY T1.checkpoint_sequence_number ASC, T1.event_seq ASC
            "#,
                        )
                        .bind(*checkpoint_guard)
                        .bind(current_seq)
                        .fetch(&mut *tx);

                        // Process each event using the callback as it's streamed from the database.
                        while let Some(event_result) = events_stream.next().await {
                            let event = event_result.map_err(|err| {
                                error!(?err, "DB error");
                                err
                            })?;

                            events_manager(
                                event.event_type,
                                event.bcs,
                                job_id.clone(),
                                job_registry.clone(),
                                infra_provider.clone(),
                                regions,
                                rates,
                                gb_rates,
                                address_whitelist,
                                address_blacklist,
                            )
                            .await
                            .map_err(|err| {
                                error!(?err, "Events Manager Error");
                                err
                            })?;

                            *checkpoint_guard = event.checkpoint_sequence_number;
                        }
                    }
                }

                // Commit the transaction after all events have been processed.
                tx.commit().await.map_err(|err| {
                    error!(?err, "DB error");
                    err
                })?;

                Ok::<_, anyhow::Error>(())
            }
        },
    )
    .await;

    let mut current_checkpoint = *current_checkpoint.lock().unwrap();

    if retry_result.is_err() {
        return current_checkpoint;
    }

    while current_checkpoint < current_seq {
        let checkpoint_retry = Retry::spawn(
            ExponentialBackoff::from_millis(100)
                .max_delay(std::time::Duration::from_secs(5))
                .map(jitter),
            || {
                let mut ledger_client = ledger_client.clone();
                async move {
                    let checkpoint = ledger_client
                        .get_checkpoint(Request::new(GetCheckpointRequest {
                            read_mask: Some(FieldMask {
                                paths: vec!["sequence_number".into(), "transactions".into()],
                            }),
                            checkpoint_id: Some(CheckpointId::SequenceNumber(
                                current_checkpoint as u64 + 1,
                            )),
                        }))
                        .await
                        .map_err(|err| {
                            error!(?err, "RPC error");
                            ()
                        })?
                        .into_inner();

                    let Some(checkpoint) = checkpoint.checkpoint else {
                        error!("Checkpoint {} data not found", current_checkpoint + 1);
                        return Err(());
                    };

                    Ok::<Checkpoint, ()>(checkpoint)
                }
            },
        )
        .await;

        let Ok(checkpoint) = checkpoint_retry else {
            return current_checkpoint;
        };

        current_checkpoint = checkpoint.sequence_number() as i64;

        for tx in checkpoint.transactions {
            let Some(events) = tx.events else {
                continue;
            };

            for event in events.events {
                if event.package_id() != job_id.contract {
                    continue;
                }

                if events_manager(
                    event.event_type().to_owned(),
                    event
                        .contents
                        .map(|cont| cont.value().to_vec())
                        .unwrap_or_default(),
                    job_id.clone(),
                    job_registry.clone(),
                    infra_provider.clone(),
                    regions,
                    rates,
                    gb_rates,
                    address_whitelist,
                    address_blacklist,
                )
                .await
                .map_err(|err| {
                    error!(?err, "Events Manager Error");
                    err
                })
                .is_err()
                {
                    return current_checkpoint;
                };
            }
        }
    }

    while let Some(log) = job_stream.next().await {
        let checkpoint = match log {
            Ok(checkpoint) => checkpoint,
            Err(err) => {
                error!(?err, "RPC error");
                return current_checkpoint;
            }
        };

        let Some(checkpoint) = checkpoint.checkpoint else {
            error!("Checkpoint {} data not found", checkpoint.cursor());
            return current_checkpoint;
        };

        current_checkpoint = checkpoint.sequence_number() as i64;

        for tx in checkpoint.transactions {
            let Some(events) = tx.events else {
                continue;
            };

            for event in events.events {
                if event.package_id() != job_id.contract {
                    continue;
                }

                if events_manager(
                    event.event_type().to_owned(),
                    event
                        .contents
                        .map(|cont| cont.value().to_vec())
                        .unwrap_or_default(),
                    job_id.clone(),
                    job_registry.clone(),
                    infra_provider.clone(),
                    regions,
                    rates,
                    gb_rates,
                    address_whitelist,
                    address_blacklist,
                )
                .await
                .map_err(|err| {
                    error!(?err, "Events Manager Error");
                    err
                })
                .is_err()
                {
                    return current_checkpoint;
                };
            }
        }
    }

    info!("Job stream ended");

    current_checkpoint
}

#[derive(Debug, FromRow)]
struct MinimalEventDetails {
    pub checkpoint_sequence_number: i64,
    pub event_type: String,
    pub bcs: Vec<u8>,
}

async fn events_manager(
    type_: String,
    contents: Vec<u8>,
    mut job_id: JobId,
    job_registry: JobRegistry,
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
) -> Result<()> {
    let (id, job_event) = match parse_log(type_.clone(), contents.clone()) {
        Ok(Some((id, event))) => (id, event),
        Ok(None) => return Ok(()),
        Err(err) => {
            return Err(anyhow!(
                "Event log parse error for {} with bcs {}: {}",
                type_,
                hex::encode(contents),
                err
            ));
        }
    };

    let tx_sender = match &job_event {
        JobEvent::Opened {
            job_id: _,
            owner: _,
            provider,
            metadata: _,
            rate: _,
            balance: _,
            timestamp: _,
        } => {
            if provider.to_owned() != job_id.operator {
                return Ok(());
            }

            info!(?id, "New job");

            job_id.id = id.to_string();

            // Skip if this job has already been terminated
            if job_registry.is_job_terminated(&job_id.id) {
                info!("Skipping already terminated job: {}", job_id.id);
                return Ok(());
            }

            if job_registry
                .active_jobs
                .lock()
                .unwrap()
                .contains_key(&job_id.id)
            {
                info!("Skipping already running job: {}", job_id.id);
                return Ok(());
            }

            let (tx, rx) = mpsc::channel::<JobEvent>(100);
            job_registry
                .active_jobs
                .lock()
                .unwrap()
                .insert(job_id.id.clone(), tx.clone());

            tokio::spawn(
                job_manager(
                    RealSystemContext {},
                    rx,
                    infra_provider,
                    job_id,
                    regions,
                    3,
                    rates,
                    gb_rates,
                    address_whitelist,
                    address_blacklist,
                    job_registry,
                )
                .instrument(info_span!(parent: None, "job", ?id)),
            );

            Some(tx)
        }
        _ => {
            let guard = job_registry.active_jobs.lock().unwrap();
            guard.get(&id.to_string()).cloned()
        }
    };

    if let Some(tx) = tx_sender {
        if let Err(err) = tx.send(job_event.clone()).await {
            return Err(anyhow!(
                "Failed to send event {:?} to the relevant job manager channel: {}",
                job_event,
                err
            ));
        }
    }

    Ok(())
}

// Registry to track jobs
#[derive(Clone)]
pub struct JobRegistry {
    active_jobs: Arc<Mutex<HashMap<String, mpsc::Sender<JobEvent>>>>,
    terminated_jobs: Arc<Mutex<HashSet<String>>>,
    save_path: String,
}

impl JobRegistry {
    pub async fn new(save_path: String) -> Result<Self> {
        let mut terminated_jobs = HashSet::new();
        // Initialize with jobs from disk if file exists
        if Path::new(&save_path).exists() {
            terminated_jobs = fs::read_to_string(&save_path)
                .await?
                .trim()
                .lines()
                .map(str::to_owned)
                .collect();
            info!(
                "Loaded {} terminated jobs from registry",
                terminated_jobs.len()
            );
        }

        Ok(JobRegistry {
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            terminated_jobs: Arc::new(Mutex::new(terminated_jobs)),
            save_path,
        })
    }

    fn add_terminated_job(&self, job_id: String) {
        self.terminated_jobs.lock().unwrap().insert(job_id);
    }

    fn remove_active_job(&self, job_id: String) {
        self.active_jobs.lock().unwrap().remove(&job_id);
    }

    fn is_job_terminated(&self, job_id: &str) -> bool {
        self.terminated_jobs.lock().unwrap().contains(job_id)
    }

    async fn save_to_disk(&self) -> Result<(), std::io::Error> {
        let jobs = self
            .terminated_jobs
            .lock()
            .unwrap()
            .iter()
            .fold("".to_owned(), |a, b| a + "\n" + b)
            .trim()
            .to_owned();
        fs::write(&self.save_path, jobs).await?;
        Ok(())
    }

    pub async fn run_periodic_save(self, interval_secs: u64) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            if let Err(e) = self.save_to_disk().await {
                error!("Failed to save job registry: {:?}", e);
            } else {
                info!(
                    "Job registry saved to disk: {} terminated jobs",
                    self.terminated_jobs.lock().unwrap().len()
                );
            }
        }
    }
}

// manage the complete lifecycle of a job
async fn job_manager(
    context: impl SystemContext + Send + Sync,
    mut events_stream: mpsc::Receiver<JobEvent>,
    mut infra_provider: impl InfraProvider + Send + Sync,
    job_id: JobId,
    allowed_regions: &[String],
    aws_delay_duration: u64,
    rates: &[RegionalRates],
    gb_rates: &[GBRateCard],
    address_whitelist: &[String],
    address_blacklist: &[String],
    job_registry: JobRegistry,
) -> JobResult {
    let mut state = JobState::new(
        &context,
        job_id.clone(),
        aws_delay_duration,
        allowed_regions,
    );

    // usually tracks the result of the last log processed
    let mut job_result = JobResult::Success;

    // The processing loop follows this:
    // Keep processing events till you hit an unsuccessful processing
    // If result is Retry or Internal, these are likely RPC issues and bugs
    // Hence just break out, the parent function handles retrying
    // If result is Done, the job is naturally "done", schedule termination
    // If result is Failed, the job ran into a user error, schedule termination
    // If job is insolvent, schedule termination
    // Once job is successfully terminated, break out
    // Insolvency and heartbeats only matter when job is not already scheduled for termination
    'event: loop {
        // compute time to insolvency
        let insolvency_duration = state.insolvency_duration();
        info!(duration = insolvency_duration.as_secs(), "Insolvency after");

        let aws_delay_timeout = state
            .infra_change_time
            .saturating_duration_since(Instant::now());

        // NOTE: some stuff like cargo fmt does not work inside this macro
        // extract as much stuff as possible outside it
        tokio::select! {
            // order matters
            // first process all logs because they might end up closing the job
            // then process insolvency because it might end up closing the job
            // then infra changes
            // then heartbeat
            // this ensures that any log which results in a job getting closed or insolvent
            // is given priority and the job is terminated even if other infra changes are
            // scheduled
            biased;

            // keep processing logs till the processing is successful
            log = events_stream.recv(), if job_result == JobResult::Success => {
                job_result = match log {
                    Some(event) => state.process_event(event, rates, gb_rates, address_whitelist, address_blacklist),
                    None => JobResult::Internal,
                };
                match job_result {
                    // just proceed
                    JobResult::Success => {},
                    // terminate
                    JobResult::Done => {
                        state.schedule_termination(0);
                    },
                    // terminate
                    JobResult::Failed => {
                        state.schedule_termination(0);
                    },
                    _ => break 'event,
                };
            }

            // insolvency check
            // enable when processing is successful
            () = sleep(insolvency_duration), if job_result == JobResult::Success => {
                state.handle_insolvency();
                job_result = JobResult::Done;
            }

            // aws delayed spin up check
            // should only happen if scheduled
            () = sleep(aws_delay_timeout), if state.infra_change_scheduled => {
                let res = state.change_infra(&mut infra_provider).await;
                if res && !state.infra_state {
                    // successful termination, exit
                    break 'event;
                }
            }

            // running instance heartbeat check
            // should only happen if infra change is not scheduled
            () = sleep(Duration::from_secs(5)), if !state.infra_change_scheduled => {
                state.heartbeat_check(&mut infra_provider).await;
            }
        }
    }

    if job_result == JobResult::Done || job_result == JobResult::Failed {
        job_registry.add_terminated_job(job_id.id.clone());
    }

    job_registry.remove_active_job(job_id.id);

    job_result
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  TESTS
// --------------------------------------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloy::hex::ToHexExt;
    use alloy::primitives::U256;
    use sui_sdk::types::base_types::SuiAddress;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration, Instant};

    use crate::market_sui;
    use crate::test::{self, compute_address_word, compute_instance_id, TestAws, TestAwsOutcome};

    use super::{JobEvent, JobResult, SystemContext};

    struct TestSystemContext {
        start: Instant,
    }

    impl SystemContext for TestSystemContext {
        fn now_timestamp(&self) -> Duration {
            Instant::now() - self.start
        }
    }

    struct JobManagerParams {
        job_id: market_sui::JobId,
        allowed_regions: Vec<String>,
        address_whitelist: Vec<String>,
        address_blacklist: Vec<String>,
    }

    struct TestResults {
        res: JobResult,
        outcomes: Vec<TestAwsOutcome>,
    }

    async fn run_test(
        start_time: Instant,
        logs: Vec<(u64, JobEvent)>,
        job_manager_params: JobManagerParams,
        test_results: TestResults,
    ) {
        let context = TestSystemContext { start: start_time };

        let (tx, rx) = mpsc::channel::<JobEvent>(10);
        let mut aws: TestAws = Default::default();
        let job_registry = market_sui::JobRegistry::new("terminated_jobs.txt".to_string())
            .await
            .unwrap();

        tokio::spawn(async move {
            for (moment, event) in logs {
                let delay = start_time + Duration::from_secs(moment) - Instant::now();
                sleep(delay).await;
                if let Err(err) = tx.send(event).await {
                    println!("{}", err);
                }
            }
        });

        let res = market_sui::job_manager(
            context,
            rx,
            &mut aws,
            job_manager_params.job_id,
            &job_manager_params.allowed_regions,
            300,
            &test::get_rates(),
            &test::get_gb_rates(),
            &job_manager_params.address_whitelist,
            &job_manager_params.address_blacklist,
            job_registry,
        )
        .await;

        assert!(aws.instances.is_empty());

        assert_eq!(res, test_results.res);
        assert_eq!(aws.outcomes, test_results.outcomes);
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (301, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (301, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_with_debug_mode_on_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (301, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: true,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up_with_specific_family() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"family\":\"tuna\"}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (301, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "tuna".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_deposit_withdraw_settle() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (40, JobEvent::Deposited {
                job_id: job_id.to_string(),
                from: SuiAddress::from_bytes(compute_address_word("depositor").0).unwrap().to_string(),
                amount: U256::from(500),
            }),
            (60, JobEvent::Withdrew {
                job_id: job_id.to_string(),
                to: SuiAddress::from_bytes(compute_address_word("withdrawer").0).unwrap().to_string(),
                amount: U256::from(500),
            }),
            (100, JobEvent::Settled {
                job_id: job_id.to_string(),
                amount: U256::from(2),
                settled_until_ms: U256::from(6),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_cancel() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (50, JobEvent::ReviseRateInitiated {
                job_id: job_id.to_string(),
                new_rate: U256::from(32000000000000u64),
            }),
            (100, JobEvent::ReviseRateFinalized {
                job_id: job_id.to_string(),
                new_rate: U256::from(32000000000000u64),
            }),
            (150, JobEvent::ReviseRateInitiated {
                job_id: job_id.to_string(),
                new_rate: U256::from(60000000000000u64),
            }),
            (200, JobEvent::ReviseRateCancelled {
                job_id: job_id.to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_region() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-east-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-east-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_region_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_type_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_instance() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_url_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_min_rate() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(29000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_exceed_balance() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(0u64),
                timestamp: U256::from(0)
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // NOTE: This scenario should be impossible based on how the contract should be written
    // Nevertheless, the cp should handle it to be defensive, so we test
    #[tokio::test(start_paused = true)]
    async fn test_withdrawal_exceed_rate() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (350, JobEvent::Withdrew { job_id: job_id.to_string(), to: SuiAddress::from_bytes(compute_address_word("withdrawer").0).unwrap().to_string(), amount: U256::from(30000u64) }),
            (500, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_lower_higher() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (350, JobEvent::ReviseRateInitiated {
                job_id: job_id.to_string(),
                new_rate: U256::from(29000000000000u64),
            }),
            (400, JobEvent::ReviseRateFinalized {
                job_id: job_id.to_string(),
                new_rate: U256::from(29000000000000u64),
            }),
            (450, JobEvent::ReviseRateInitiated {
                job_id: job_id.to_string(),
                new_rate: U256::from(31000000000000u64),
            }),
            (500, JobEvent::ReviseRateFinalized {
                job_id: job_id.to_string(),
                new_rate: U256::from(31000000000000u64),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_whitelisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (500, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("owner").encode_hex_with_prefix()],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_whitelisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (500, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("notowner").encode_hex_with_prefix()],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_blacklisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (500, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("owner").encode_hex_with_prefix()],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_blacklisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (500, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("notowner").encode_hex_with_prefix()],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (100, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_debug_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (100, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (100, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(100),
                job: job_id.to_string(),
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (100, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (100, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (400, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_debug_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (400, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: true,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (400, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (400, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, JobEvent::Opened {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
                owner: SuiAddress::from_bytes(compute_address_word("owner").0).unwrap().to_string(),
                provider: SuiAddress::from_bytes(compute_address_word("provider").0).unwrap().to_string(),
                rate: U256::from(31000000000000u64),
                balance: U256::from(31000u64),
                timestamp: U256::from(0)
            }),
            (400, JobEvent::MetadataUpdated {
                job_id: job_id.to_string(),
                metadata: "{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),
            }),
            (505, JobEvent::Closed {
                job_id: job_id.to_string(),
            }),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market_sui::JobId {
                id: job_id.to_string(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.to_string(),
                    instance_type: "c6a.xlarge".into(),
                    family: "salmon".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    debug: false,
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id.to_string(),
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }
}
