use crate::commands::subscription::types::{RelayContract, RelaySubscriptions, TerminateArgs};
use crate::configs::global::{RELAY_CONTRACT_ADDRESS, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS};
use crate::utils::provider::create_provider;
use alloy::hex;
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::sol_types::SolError;
use anyhow::{anyhow, Context, Result};
use tracing::info;

pub async fn terminate(args: TerminateArgs) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    //Fetch tx receipt
    let tx_receipt = provider
        .get_transaction_receipt(args.subscription_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    let data =
        tx_receipt.inner.logs()[0].log_decode::<RelaySubscriptions::JobSubscriptionStarted>()?;

    let subscription_id = data.data().jobSubsId;
    info!("Subscription ID: {:?}", subscription_id);

    let relay_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;
    let relay_subscription_contract =
        RelaySubscriptions::new(relay_subscription_contract_address, provider.clone());

    let relay_contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let relay_contract = RelayContract::new(relay_contract_address, provider.clone());

    let overall_timeout = relay_contract
        .OVERALL_TIMEOUT()
        .call()
        .await
        .context("Failed to get overall timeout")?
        ._0
        * U256::from(2);

    let terminate_tx = match relay_subscription_contract
        .terminateJobSubscription(subscription_id)
        .send()
        .await
    {
        Ok(tx) => tx,
        Err(err) => {
            let err_str = err.to_string();
            let not_owner = hex::encode(
                RelaySubscriptions::RelaySubscriptionsNotJobSubscriptionOwner::SELECTOR,
            )
            .to_string();
            let invalid_timestamp = hex::encode(
                RelaySubscriptions::RelaySubscriptionsInvalidTerminationTimestamp::SELECTOR,
            )
            .to_string();
            let subscription_terminated = hex::encode(
                RelaySubscriptions::RelaySubscriptionsJobSubscriptionTerminated::SELECTOR,
            )
            .to_string();
            let insufficient_callback = hex::encode(
                RelaySubscriptions::RelaySubscriptionsInsufficientCallbackDeposit::SELECTOR,
            )
            .to_string();
            let insufficient_usdc = hex::encode(
                RelaySubscriptions::RelaySubscriptionsInsufficientUsdcDeposit::SELECTOR,
            )
            .to_string();

            if err_str.contains(&not_owner) {
                return Err(anyhow!("Transaction reverted: Not the subscription owner"));
            } else if err_str.contains(&invalid_timestamp) {
                return Err(anyhow!(
                    "Transaction reverted: Invalid termination timestamp"
                ));
            } else if err_str.contains(&subscription_terminated) {
                info!("If you plan to execute the refund-deposits command next, please make sure that at least {} seconds have passed since the terminate-subscription transaction.", overall_timeout);
                return Err(anyhow!(
                    "Transaction reverted: Subscription already terminated."
                ));
            } else if err_str.contains(&insufficient_callback) {
                return Err(anyhow!(
                    "Transaction reverted: Insufficient callback deposit"
                ));
            } else if err_str.contains(&insufficient_usdc) {
                return Err(anyhow!("Transaction reverted: Insufficient USDC deposit"));
            }
            return Err(anyhow!("Contract error: {}", err_str));
        }
    };

    let terminate_receipt = terminate_tx
        .get_receipt()
        .await
        .context("Failed to get transaction receipt")?;

    info!(
        "Transaction hash for terminate subscription transaction: {:?}",
        terminate_receipt.transaction_hash
    );

    info!(
        "If you plan to execute the refund-deposits command next, please wait at least {} seconds.",
        overall_timeout
    );

    Ok(())
}
