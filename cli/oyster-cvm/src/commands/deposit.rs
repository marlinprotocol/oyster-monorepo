use std::str::FromStr;

use crate::args::wallet::WalletArgs;
use crate::configs::global::MIN_DEPOSIT_AMOUNT;
use crate::deployment::adapter::JobTransactionKind;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::{ask_yes_no, deposit_impact, format_duration, format_usdc, is_interactive};
use alloy::primitives::U256;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_sdk_types::Address;
use tracing::{info, warn};

// The operator stops an enclave about this long before its balance runs out
const OPERATOR_STOP_BUFFER_SECS: u64 = 300;

/// Deposit funds to an existing job
#[derive(Args)]
pub struct DepositArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short, long, required = true)]
    job_id: String,

    /// Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required = true)]
    amount: u64,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// USDC coin ID for Sui chain based enclave payment (optional, will be picked automatically from user's account if not provided)
    #[arg(long)]
    usdc_coin: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,

    /// Do not ask for confirmation before depositing
    #[arg(short = 'y', long)]
    yes: bool,

    /// Deposit even if the job has already run out of balance.
    /// The market then takes the cost of the time since the job's last settlement
    /// out of the deposit first, see the warning the command prints.
    #[arg(long)]
    force: bool,
}

pub async fn deposit_to_job(args: DepositArgs) -> Result<()> {
    info!("Starting deposit...");

    let amount = args.amount;
    let force = args.force;
    let yes = args.yes;
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;

    // Input validation
    if amount < MIN_DEPOSIT_AMOUNT {
        return Err(anyhow!(
            "Amount must be at least {} (0.000001 USDC)",
            MIN_DEPOSIT_AMOUNT
        ));
    }

    // Convert amount to U256 with 6 decimals (USDC has 6 decimals)
    let amount_u256 = U256::from(amount);

    let mut deployment_adapter = get_deployment_adapter(
        args.deployment,
        args.rpc,
        args.auth_token,
        args.usdc_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
        args.gas_coin
            .map(|coin| Address::from_str(&coin))
            .transpose()?,
    );

    // Setup provider
    let provider = deployment_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Check if job exists
    let Some(job_data) = deployment_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?
    else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    let extra_decimals = deployment_adapter.fetch_extra_decimals(&provider).await?;
    info!(
        "Depositing: {:.6} USDC",
        format_usdc(amount_u256, extra_decimals)
    );

    // The market does not settle a job on deposit. Work out from the job state on chain
    // what the next settlement will do with this deposit.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();
    let impact = deposit_impact(
        job_data.balance,
        job_data.rate,
        job_data.last_settled,
        now,
        extra_decimals,
        amount_u256,
    );

    let mut confirmed = yes;
    if impact.ran_out {
        warn!(
            "Job {} ran out of balance {} ago.",
            job_id,
            format_duration(impact.ran_out_secs_ago)
        );
        warn!(
            "The market charges a job for all the time since its last settlement, whether the enclave was running or not, and takes it from the balance including this deposit."
        );
        if impact.usable.is_zero() {
            warn!(
                "The whole deposit of {:.6} USDC would go to the operator for time that has already passed. Nothing would be left to run the job.",
                format_usdc(amount_u256, extra_decimals)
            );
        } else {
            warn!(
                "{:.6} USDC of this deposit would go to the operator for time that has already passed, {:.6} USDC would be left to run the job ({}).",
                format_usdc(impact.to_gap, extra_decimals),
                format_usdc(impact.usable, extra_decimals),
                impact
                    .secs_after_deposit
                    .map(format_duration)
                    .unwrap_or_default()
            );
        }
        warn!(
            "The operator has most likely stopped the enclave already. Consider stopping this job and deploying a new one instead."
        );

        if force {
            warn!("Continuing because of --force.");
        } else if is_interactive() {
            if !ask_yes_no("Deposit anyway?")? {
                return Err(anyhow!("Deposit cancelled, nothing was paid"));
            }
            confirmed = true;
        } else {
            return Err(anyhow!(
                "Job {} has run out of balance, refusing to deposit. Pass --force to deposit anyway",
                job_id
            ));
        }
    } else {
        info!(
            "Current balance: {:.6} USDC",
            format_usdc(impact.current_balance, extra_decimals)
        );
        if let Some(secs) = impact.secs_after_deposit {
            info!(
                "Balance after deposit lasts about {} at the current rate",
                format_duration(secs)
            );
        }

        let current_secs_left = (!job_data.rate.is_zero()).then(|| {
            deposit_impact(
                job_data.balance,
                job_data.rate,
                job_data.last_settled,
                now,
                extra_decimals,
                U256::ZERO,
            )
            .secs_after_deposit
            .unwrap_or(0)
        });
        if let Some(secs) = current_secs_left
            && secs <= OPERATOR_STOP_BUFFER_SECS
        {
            warn!(
                "The job has only {} of balance left. Operators stop an enclave about {} before its balance runs out, so it may already be stopped.",
                format_duration(secs),
                format_duration(OPERATOR_STOP_BUFFER_SECS)
            );
        }
    }

    // Nothing has been paid so far, the approval and the deposit transaction follow
    if !confirmed
        && is_interactive()
        && !ask_yes_no(&format!(
            "Deposit {:.6} USDC into job {}?",
            format_usdc(amount_u256, extra_decimals),
            job_id
        ))?
    {
        return Err(anyhow!("Deposit cancelled, nothing was paid"));
    }

    // First approve USDC transfer
    let funds = deployment_adapter
        .prepare_funds(amount_u256, &provider)
        .await?;

    let job_deposit_transaction = deployment_adapter
        .create_job_transaction(
            JobTransactionKind::Deposit {
                job_id,
                amount: amount_u256,
            },
            Some(funds),
            &provider,
        )
        .await?;

    // Call jobDeposit function
    let _ = deployment_adapter
        .send_transaction(false, job_deposit_transaction, &provider)
        .await?;

    info!("Deposit successful!");

    Ok(())
}
