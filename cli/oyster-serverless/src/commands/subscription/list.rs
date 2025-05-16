use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    commands::subscription::types::ListSubscriptionArgs,
    configs::global::{ARBITRUM_ONE_RPC_URL, INDEXER_URL, RELAY_CONTRACT_ADDRESS},
    utils::conversion::string_epoch_to_local_datetime,
};
use alloy::{primitives::U256, providers::ProviderBuilder};
use anyhow::{Context, Result};
use prettytable::{row, Table};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use super::types::RelayContract;

#[derive(Deserialize, Debug)]
struct SubscriptionNode {
    #[serde(rename = "txHash")]
    tx_hash: String,
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "terminationTime")]
    termination_time: String,
    #[serde(rename = "periodicity")]
    periodicity: String,
    #[serde(rename = "isCompleted")]
    is_completed: bool,
    #[serde(rename = "numberOfRuns")]
    number_of_runs: String,
}

#[derive(Deserialize, Debug)]
struct SubscriptionEdge {
    node: SubscriptionNode,
}

#[derive(Deserialize, Debug)]
struct AllSubscriptions {
    #[serde(rename = "totalCount")]
    total_count: i32,
    edges: Vec<SubscriptionEdge>,
}

#[derive(Deserialize, Debug)]
struct GraphQLResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<serde_json::Value>>,
}

fn get_current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as i64
}

/// List subscriptions for a given address
pub async fn list_subscriptions(args: ListSubscriptionArgs) -> Result<()> {
    // Create provider
    let rpc_url = ARBITRUM_ONE_RPC_URL
        .parse()
        .context("Failed to parse RPC URL")?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    // Parse addresses
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;

    // Create contract instance
    let contract = RelayContract::new(contract_address, provider.clone());

    let overall_timeout = contract
        .OVERALL_TIMEOUT()
        .call()
        .await
        .context("Failed to fetch overall timeout")?
        ._0;

    let time_condition = U256::from(get_current_timestamp()) - overall_timeout;

    let client = reqwest::Client::new();

    let termination_filter = if args.completed {
        json!({
            "lessThan": time_condition,
        })
    } else {
        json!({
            "greaterThanOrEqualTo": time_condition
        })
    };

    let query = json!({
        "query": r#"
            query($address: String!, $terminationFilter: BigFloatFilter!) {
                allSubscriptions(
                    filter: {
                        owner: { equalToInsensitive: $address },
                        terminationTime: $terminationFilter
                    }
                ) {
                    totalCount
                    edges {
                        node {
                            txHash
                            startTime
                            terminationTime
                            periodicity
                            isCompleted
                            numberOfRuns
                        }
                    }
                }
            }
        "#,
        "variables": {
            "address": args.address,
            "terminationFilter": termination_filter
        }
    });

    let response = client
        .post(INDEXER_URL)
        .header("Content-Type", "application/json")
        .json(&query)
        .send()
        .await?;

    let response_data: GraphQLResponse = response.json().await?;

    if let Some(errors) = response_data.errors {
        anyhow::bail!("GraphQL query failed: {:?}", errors);
    }

    let mut table = Table::new();
    table.add_row(row![
        "Transaction hash",
        "Start time",
        "Termination time",
        "Periodicity",
        "Number of runs",
        "Status"
    ]);

    if let Some(data) = response_data.data {
        let all_subscriptions: AllSubscriptions =
            serde_json::from_value(data["allSubscriptions"].clone())?;

        info!("Found {} subscriptions", all_subscriptions.total_count);

        for edge in all_subscriptions.edges {
            let subscription = edge.node;
            let status = if args.completed {
                if subscription.is_completed {
                    "REFUNDED"
                } else {
                    "REFUNDABLE"
                }
            } else {
                "ACTIVE"
            };

            table.add_row(row![
                subscription.tx_hash,
                string_epoch_to_local_datetime(subscription.start_time)?,
                string_epoch_to_local_datetime(subscription.termination_time)?,
                subscription.periodicity,
                subscription.number_of_runs,
                status
            ]);
        }
        if all_subscriptions.total_count > 0 {
            table.printstd();
        }
    }

    Ok(())
}
