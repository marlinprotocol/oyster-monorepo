use crate::commands::subscription::types::{RefundDepositsArgs, RelaySubscriptions};
use crate::configs::global::RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS;
use crate::utils::provider::create_provider;
use alloy::hex;
use alloy::providers::Provider;
use alloy::sol_types::SolError;
use anyhow::{anyhow, Context, Result};
use tracing::info;

pub async fn refund_deposits(args: RefundDepositsArgs) -> Result<()> {
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

    let refund_tx = match relay_subscription_contract
        .refundJobSubsDeposits(subscription_id)
        .send()
        .await
    {
        Ok(tx) => tx,
        Err(err) => {
            let err_str = err.to_string();
            let not_exists =
                hex::encode(RelaySubscriptions::RelaySubscriptionsNotExists::SELECTOR).to_string();
            let termination_pending = hex::encode(
                RelaySubscriptions::RelaySubscriptionsTerminationConditionPending::SELECTOR,
            )
            .to_string();

            if err_str.contains(&not_exists) {
                return Err(anyhow!("Transaction reverted: Subscription does not exist"));
            } else if err_str.contains(&termination_pending) {
                return Err(anyhow!(
                    "Transaction reverted: Termination condition is still pending"
                ));
            }
            return Err(anyhow!("Contract error: {}", err_str));
        }
    };

    let refund_receipt = refund_tx
        .get_receipt()
        .await
        .context("Failed to get transaction receipt")?;

    info!(
        "Transaction hash for refund transaction: {:?}",
        refund_receipt.transaction_hash
    );

    Ok(())
}
