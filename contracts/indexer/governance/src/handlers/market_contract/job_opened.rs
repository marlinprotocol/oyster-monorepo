use alloy::hex::ToHexExt;
use alloy::primitives::Address;
use alloy::primitives::U256;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use serde_json::Value;
use tracing::{info, instrument, warn};

use crate::schema::proposals;

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_opened(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing job opened");

    let job_id = log.topics()[1].encode_hex_with_prefix();
    let owner = Address::from_word(log.topics()[2]).to_checksum(None);
    let provider = Address::from_word(log.topics()[3]).to_checksum(None);
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .encode_hex_with_prefix();

    let (metadata, _rate, _balance, _timestamp) =
        <(String, U256, U256, U256)>::abi_decode_sequence(&log.data().data, true)?;

    info!(?tx_hash, "Job Opened for proposal");

    info!(
        ?job_id,
        ?owner,
        ?provider,
        ?tx_hash,
        "Job Opened for proposal"
    );

    // Parse metadata as JSON
    let json_metadata: Value = match serde_json::from_str(&metadata) {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!(
                ?metadata,
                ?e,
                "Failed to parse metadata as JSON, skipping proposal_id extraction"
            );
            return Ok(());
        }
    };

    // Extract init_params from JSON
    let init_params_base64 = match json_metadata.get("init_params") {
        Some(params) => match params.as_str() {
            Some(base64_str) => base64_str,
            None => {
                warn!("init_params is not a string, skipping proposal_id extraction");
                return Ok(());
            }
        },
        None => {
            warn!("No init_params found in metadata, skipping proposal_id extraction");
            return Ok(());
        }
    };

    // Decode base64 init_params
    let init_params_json = match general_purpose::STANDARD.decode(init_params_base64) {
        Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
            Ok(json_str) => json_str,
            Err(e) => {
                warn!(?e, "Failed to convert decoded bytes to UTF-8 string");
                return Ok(());
            }
        },
        Err(e) => {
            warn!(?e, "Failed to decode base64 init_params");
            return Ok(());
        }
    };

    // Parse the decoded JSON
    let init_params: Value = match serde_json::from_str(&init_params_json) {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!(
                ?init_params_json,
                ?e,
                "Failed to parse decoded init_params as JSON"
            );
            return Ok(());
        }
    };

    // Find the object with path "params/proposal_id"
    let proposal_id_base64 = match init_params.get("params") {
        Some(params_array) => match params_array.as_array() {
            Some(params) => {
                let mut proposal_id_content = None;
                for param in params {
                    if let Some(path) = param.get("path") {
                        if path.as_str() == Some("params/proposal_id") {
                            if let Some(contents) = param.get("contents") {
                                if let Some(contents_str) = contents.as_str() {
                                    proposal_id_content = Some(contents_str);
                                    break;
                                }
                            }
                        }
                    }
                }
                proposal_id_content
            }
            None => {
                warn!("params is not an array");
                None
            }
        },
        None => {
            warn!("No params found in init_params");
            None
        }
    };

    let proposal_id_base64 = match proposal_id_base64 {
        Some(id) => id,
        None => {
            info!("No object with path 'params/proposal_id' found, not a governance job");
            return Ok(());
        }
    };

    // Decode the proposal_id from base64
    let proposal_id_hex = match general_purpose::STANDARD.decode(proposal_id_base64) {
        Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
            Ok(hex_str) => hex_str,
            Err(e) => {
                warn!(
                    ?e,
                    "Failed to convert proposal_id decoded bytes to UTF-8 string"
                );
                return Ok(());
            }
        },
        Err(e) => {
            warn!(?e, "Failed to decode proposal_id from base64");
            return Ok(());
        }
    };

    info!(?proposal_id_hex, "Found proposal_id for governance job");

    // Update the proposals table with the job_id
    let count = diesel::update(proposals::table)
        .filter(proposals::id.eq(&proposal_id_hex))
        .set(proposals::job_id.eq(Some(&job_id)))
        .execute(conn)
        .context("Failed to update proposal with job_id")?;

    if count != 1 {
        return Err(anyhow::anyhow!(
            "No proposal found for proposal_id: {}",
            proposal_id_hex
        ));
    }

    info!(
        ?proposal_id_hex,
        ?job_id,
        "Successfully updated proposal with job_id"
    );

    Ok(())
}
