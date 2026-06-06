use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use reqwest::Url;
use serde_json::Value;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tracing::{error, warn};

pub async fn call_secret_store_endpoint_post(
    port: u16,
    endpoint: &str,
    request_json: Value,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let client = reqwest::Client::new();
    let req_url = "http://127.0.0.1:".to_string() + &port.to_string() + endpoint;

    let response = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            client
                .post(req_url.clone())
                .json(&request_json.clone())
                .send()
                .await
        },
    )
    .await
    .map_err(|err| {
        error!(
            %req_url,
            "Failed to send request to the secret store POST endpoint: {:?}",
            err
        );
        err
    })?;

    parse_response(response).await
}

pub async fn call_secret_store_endpoint_get(
    port: u16,
    endpoint: &str,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let client = reqwest::Client::new();
    let req_url = "http://127.0.0.1:".to_string() + &port.to_string() + endpoint;

    let response = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async { client.get(req_url.clone()).send().await },
    )
    .await
    .map_err(|err| {
        error!(
            %req_url,
            "Failed to send request to secret store GET endpoint: {:?}",
            err
        );
        err
    })?;

    parse_response(response).await
}

async fn parse_response(
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, String, Option<Value>), reqwest::Error> {
    let status_code = response.status();

    let mut response_body = String::new();
    let mut response_json = None;

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        response_json = Some(response.json::<Value>().await.map_err(|err| {
            warn!(
                %status_code,
                "Failed to parse the response json from the secret store response: {:?}",
                err
            );
            err
        })?);
    } else {
        response_body = response.text().await.map_err(|err| {
            warn!(
                %status_code,
                "Failed to parse the response body from the secret store response: {:?}",
                err
            );
            err
        })?;
    }

    Ok((status_code, response_body, response_json))
}

pub async fn get_latest_block_number(http_rpc_url: &String) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    http_rpc_client
        .get_block_number()
        .await
        .context("Failed to get a response from the rpc server")
}

pub fn get_byte_slice(num: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = num;
    bytes
}
