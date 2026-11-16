use crate::args::wallet::WalletArgs;
use crate::deployment::adapter::{JobTransactionKind, RateLock};
use crate::deployment::{Deployment, get_deployment_adapter};
use alloy::primitives::U256;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use std::str::FromStr;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::time::sleep;
use tracing::{info, warn};

// Seconds added to the remaining notice period before the close is attempted
const CLOSE_MARGIN_SECS: u64 = 3;
// Interval between lock checks when the chain does not expose the unlock time
const LOCK_POLL_INTERVAL_SECS: u64 = 10;
// Close attempts before giving up
const CLOSE_ATTEMPTS: u32 = 5;
const CLOSE_RETRY_INTERVAL_SECS: u64 = 10;
// Lock reads after a stop request before concluding that it did not land
const LOCK_VISIBILITY_CHECKS: u32 = 5;

/// Stop an Oyster CVM instance
///
/// Sends a stop request (a rate revision to 0), waits for the notice period of the market
/// and then closes the job, which refunds the unused balance.
/// The job keeps billing until the close transaction lands.
/// If the command is interrupted, run it again with the same arguments:
/// it reads the pending stop request from the chain, waits only for what is left and closes the job.
#[derive(Args)]
pub struct StopArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short = 'j', long, required = true)]
    job_id: String,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,

    /// Send the stop request and exit without waiting for the notice period.
    /// The job keeps billing until this command is run again to close it.
    #[arg(long)]
    no_wait: bool,
}

/// What `stop` has to do next for a job, given its rate and its rate lock.
#[derive(Debug, PartialEq, Eq)]
enum StopStep {
    /// No stop request yet, send the rate revision to 0.
    Initiate,
    /// A stop request is pending, wait for the rest of the notice period.
    Wait(Option<u64>),
    /// The job can be closed now.
    Close,
    /// A rate revision to a non-zero rate is pending, the contract refuses to close.
    Blocked(U256),
}

fn next_stop_step(job_rate: U256, lock: &RateLock) -> StopStep {
    // the market closes zero rate jobs without notice
    if job_rate.is_zero() {
        return StopStep::Close;
    }

    match lock {
        RateLock::None => StopStep::Initiate,
        RateLock::Pending {
            new_rate: Some(rate),
            ..
        }
        | RateLock::Matured {
            new_rate: Some(rate),
        } if !rate.is_zero() => StopStep::Blocked(*rate),
        RateLock::Pending { remaining_secs, .. } => StopStep::Wait(*remaining_secs),
        RateLock::Matured { .. } => StopStep::Close,
    }
}

pub async fn stop_oyster_instance(args: StopArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;

    info!("Stopping oyster instance with:");
    info!("  Job ID: {}", job_id);

    let mut deployment_adapter = get_deployment_adapter(
        args.deployment,
        args.rpc,
        args.auth_token,
        None,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    // Setup provider
    let provider = deployment_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    info!(
        "Signer address: {:?}",
        deployment_adapter.get_sender_address()
    );

    // Check if job exists
    let Some(mut job_data) = deployment_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?
    else {
        return Err(anyhow!(
            "Job {} does not exist or is already closed",
            job_id
        ));
    };

    let mut initiated = false;
    let mut waited_secs = 0u64;
    let mut close_attempts = 0u32;
    let mut visibility_checks = 0u32;

    loop {
        let lock = deployment_adapter
            .get_rate_lock(&job_id, &provider)
            .await
            .context("Failed to read the stop request of the job")?;

        match next_stop_step(job_data.rate, &lock) {
            StopStep::Blocked(rate) => {
                return Err(anyhow!(
                    "Job {} has a pending rate revision to {} instead of a stop request. \
                     It has to be cancelled or finalized on the market contract before the job can be stopped.",
                    job_id,
                    rate
                ));
            }
            StopStep::Initiate => {
                if initiated {
                    // the node may lag behind the transaction for a moment
                    if visibility_checks < LOCK_VISIBILITY_CHECKS {
                        visibility_checks += 1;
                        sleep(Duration::from_secs(CLOSE_MARGIN_SECS)).await;
                        continue;
                    }
                    return Err(anyhow!(
                        "Stop request was sent but is not visible on chain yet. \
                         The job is still open and billing, run the same command again to continue."
                    ));
                }

                let wait_time = deployment_adapter
                    .get_rate_lock_wait_time(&provider)
                    .await
                    .context("Failed to read the notice period")?;
                info!(
                    "Found job, sending stop request (rate revision to 0). Notice period is {} seconds.",
                    wait_time
                );
                info!(
                    "The job keeps billing at its current rate until it is closed after the notice period."
                );

                let sent = async {
                    let transaction = deployment_adapter
                        .create_job_transaction(
                            JobTransactionKind::ReviseRateInitiate {
                                job_id: job_id.clone(),
                                rate: U256::from(0),
                            },
                            None,
                            &provider,
                        )
                        .await?;
                    deployment_adapter
                        .send_transaction(false, transaction, &provider)
                        .await
                }
                .await;
                initiated = true;

                if let Err(err) = sent {
                    // the transaction might still have landed, the chain decides
                    let lock = deployment_adapter
                        .get_rate_lock(&job_id, &provider)
                        .await
                        .context("Failed to read the stop request of the job")?;
                    if lock == RateLock::None {
                        return Err(err.context(
                            "Failed to send stop request, the job is still open and billing",
                        ));
                    }
                    warn!(
                        "Stop request reported an error but is present on chain, continuing: {err:#}"
                    );
                } else {
                    info!("Stop request sent.");
                }
            }
            StopStep::Wait(remaining) => {
                if !initiated && waited_secs == 0 {
                    info!("A stop request already exists for this job, resuming it.");
                }

                if args.no_wait {
                    match remaining {
                        Some(secs) => info!("Notice period ends in {} seconds.", secs),
                        None => info!("Notice period is still running."),
                    }
                    warn!(
                        "Job {} is NOT closed and keeps billing. Run the same command again after the notice period to close it and get the unused balance back.",
                        job_id
                    );
                    return Ok(());
                }

                let secs = match remaining {
                    Some(secs) => {
                        let secs = secs + CLOSE_MARGIN_SECS;
                        info!(
                            "Waiting {} seconds for the notice period to end before closing the job...",
                            secs
                        );
                        secs
                    }
                    None => {
                        if waited_secs == 0 {
                            info!("Waiting for the notice period to end before closing the job...");
                        }
                        LOCK_POLL_INTERVAL_SECS
                    }
                };
                if waited_secs == 0 {
                    info!(
                        "The job keeps billing until the close transaction lands. If this command is interrupted, run it again to finish the stop."
                    );
                }
                sleep(Duration::from_secs(secs)).await;
                waited_secs += secs;
            }
            StopStep::Close => {
                if !initiated && waited_secs == 0 && close_attempts == 0 && !job_data.rate.is_zero()
                {
                    info!(
                        "A stop request already exists for this job and its notice period is over."
                    );
                }
                info!("Closing the job...");
                close_attempts += 1;

                let sent = async {
                    let transaction = deployment_adapter
                        .create_job_transaction(
                            JobTransactionKind::Close {
                                job_id: job_id.clone(),
                            },
                            None,
                            &provider,
                        )
                        .await?;
                    deployment_adapter
                        .send_transaction(false, transaction, &provider)
                        .await
                }
                .await;

                match sent {
                    Ok(_) => {
                        info!("Instance stopped successfully! The unused balance was returned.");
                        return Ok(());
                    }
                    Err(err) if close_attempts >= CLOSE_ATTEMPTS => {
                        return Err(err.context(format!(
                            "Failed to close job {job_id} after {CLOSE_ATTEMPTS} attempts. \
                             The job may still be open and billing, run the same command again to finish the stop"
                        )));
                    }
                    Err(err) => {
                        warn!(
                            "Close attempt {}/{} failed, the job keeps billing until it is closed. Retrying in {} seconds: {err:#}",
                            close_attempts, CLOSE_ATTEMPTS, CLOSE_RETRY_INTERVAL_SECS
                        );
                        sleep(Duration::from_secs(CLOSE_RETRY_INTERVAL_SECS)).await;
                    }
                }
            }
        }

        // the chain is the source of truth for every step
        match deployment_adapter
            .get_job_data_if_exists(job_id.clone(), &provider)
            .await?
        {
            Some(data) => job_data = data,
            None => {
                info!("Job is closed.");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: U256 = U256::from_limbs([14225699361165, 0, 0, 0]);

    #[test]
    fn fresh_job_gets_a_stop_request() {
        assert_eq!(next_stop_step(RATE, &RateLock::None), StopStep::Initiate);
    }

    #[test]
    fn interrupted_stop_waits_only_for_what_is_left() {
        let lock = RateLock::Pending {
            remaining_secs: Some(42),
            new_rate: Some(U256::ZERO),
        };
        assert_eq!(next_stop_step(RATE, &lock), StopStep::Wait(Some(42)));

        // chains that do not expose the unlock time are polled
        let lock = RateLock::Pending {
            remaining_secs: None,
            new_rate: None,
        };
        assert_eq!(next_stop_step(RATE, &lock), StopStep::Wait(None));
    }

    #[test]
    fn matured_stop_request_closes_at_once() {
        let lock = RateLock::Matured {
            new_rate: Some(U256::ZERO),
        };
        assert_eq!(next_stop_step(RATE, &lock), StopStep::Close);
        assert_eq!(
            next_stop_step(RATE, &RateLock::Matured { new_rate: None }),
            StopStep::Close
        );
    }

    #[test]
    fn zero_rate_job_closes_without_notice() {
        assert_eq!(next_stop_step(U256::ZERO, &RateLock::None), StopStep::Close);
    }

    #[test]
    fn revision_to_non_zero_rate_cannot_be_closed() {
        let rate = U256::from(5);
        let lock = RateLock::Pending {
            remaining_secs: Some(10),
            new_rate: Some(rate),
        };
        assert_eq!(next_stop_step(RATE, &lock), StopStep::Blocked(rate));
        let lock = RateLock::Matured {
            new_rate: Some(rate),
        };
        assert_eq!(next_stop_step(RATE, &lock), StopStep::Blocked(rate));
    }
}
