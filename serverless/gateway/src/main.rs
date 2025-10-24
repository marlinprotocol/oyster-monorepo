mod api_impl;
mod chain_util;
mod common_chain_gateway_state_service;
mod common_chain_interaction;
mod config;
mod constant;
mod contract_abi;
mod error;
mod job_subscription_management;
mod model;

#[cfg(test)]
mod test_util;

use alloy::primitives::Address;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::utils::public_key_to_address;
use alloy::transports::http::reqwest::Url;
use anyhow::Context;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use http_on_vsock_server::{VsockAddrParser, VsockServer};
use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use tokio::fs;
use tokio_vsock::VsockListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::api_impl::{
    export_signed_registration_message, get_gateway_details, index, inject_immutable_config,
    inject_mutable_config,
};
use crate::model::{AppState, ConfigManager};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(
        long,
        value_parser,
        default_value = "./oyster_serverless_gateway_config.json"
    )]
    config_file: String,

    #[clap(short, long, value_parser = VsockAddrParser{})]
    vsock_addr: (u32, u32),
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    // Load the configuration file
    let args = Cli::parse();
    let config_manager = ConfigManager::new(&args.config_file);
    let mut config = config_manager.load_config().unwrap();

    match Url::parse(&config.common_chain_http_url) {
        Ok(_) => (),
        Err(err) => {
            error!("Invalid common chain http url: {}", err);
            return Err(err.into());
        }
    }

    match Url::parse(&config.common_chain_ws_url) {
        Ok(_) => (),
        Err(err) => {
            error!("Invalid common chain ws url: {}", err);
            return Err(err.into());
        }
    }

    if !config.common_chain_ws_url.ends_with('/') {
        config.common_chain_ws_url.push('/');
    }

    let enclave_signer_key: SigningKey = SigningKey::from_slice(
        fs::read(config.enclave_secret_key)
            .await
            .context("Failed to read the enclave signer key")?
            .as_slice(),
    )
    .context("Invalid enclave signer key")?;

    let enclave_address = public_key_to_address(&enclave_signer_key.verifying_key());

    info!("Enclave address: {}", enclave_address);

    // Create a Appstate
    let app_data = AppState {
        enclave_signer_key,
        enclave_address,
        wallet: Arc::new(RwLock::new(String::new())),
        common_chain_id: config.common_chain_id,
        common_chain_http_url: config.common_chain_http_url,
        common_chain_ws_url: config.common_chain_ws_url,
        gateways_contract_addr: config.gateways_contract_addr,
        gateway_jobs_contract_addr: config.gateway_jobs_contract_addr,
        request_chain_ids: Arc::new(Mutex::new(HashSet::new())),
        registered: Arc::new(AtomicBool::new(false)),
        epoch: config.epoch,
        time_interval: config.time_interval,
        offset_for_epoch: config.offset_for_epoch,
        enclave_owner: Arc::new(Mutex::new(Address::ZERO)),
        immutable_params_injected: Arc::new(Mutex::new(false)),
        mutable_params_injected: Arc::new(AtomicBool::new(false)),
        registration_events_listener_active: Arc::new(Mutex::new(false)),
        contracts_client: Arc::new(Mutex::new(None)),
        ws_api_key: Arc::new(RwLock::new(String::new())),
    };

    // Create App using Router
    let app = Router::new()
        .route("/", get(index))
        .route("/immutable-config", post(inject_immutable_config))
        .route("/mutable-config", post(inject_mutable_config))
        .route("/gateway-details", get(get_gateway_details))
        .route(
            "/signed-registration-message",
            post(export_signed_registration_message),
        )
        .with_state(app_data);

    let server = axum::Server::builder(VsockServer {
        listener: VsockListener::bind(args.vsock_addr.0, args.vsock_addr.1)
            .context("failed to create vsock listener")?,
    })
    .serve(app.into_make_service());

    info!("Node server started on port {:?}", args.vsock_addr);

    server.await.context("server exited with error")?;

    Ok(())
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
