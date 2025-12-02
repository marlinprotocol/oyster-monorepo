#[allow(unused)]
use crate::{
    attestations::{AttestationSource, ContractAttestationSource, EnclaveAttestationSource},
    config::{self, create_config, create_gov_chain_rpc_url, delete_config_file, latest_block},
    governance_enclave::GovernanceEnclave,
    kms::kms::KMS,
    vote_parser::VoteParse,
    vote_registry::VoteRegistry,
    vote_result::{self, ContractDataPreimage},
};
use actix_web::{
    HttpResponse, Responder,
    web::{self, Data},
};
use alloy::{
    network::Ethereum,
    primitives::{B256, U256},
    sol,
};
use anyhow::Result;
use ecies::PublicKey as EncryptionPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

/// Fetch `proposal_time_info` and validate its timestamps.
/// On RPC error -> map with `ErrorInternalServerError`.
/// On invalid timestamps -> early-return 400 { "message": "invalid proposal id" }.
///
/// Usage:
///   let proposal_time_info = fetch_and_check_proposal_time_info!(governance, proposal_id);
#[macro_export]
macro_rules! fetch_and_check_proposal_time_info {
    // Default arm: uses a standard JSON 400 mapper
    ($governance:expr, $proposal_id:expr) => {{
        let __info = $governance
            .get_proposal_timing_info($proposal_id)
            .await
            .map_err(|e| {
                let body = serde_json::json!({
                    "status": false,
                    "message": format!("proposal timing error: {e}"),
                });

                actix_web::error::InternalError::new(
                    body,
                    actix_web::http::StatusCode::BAD_REQUEST,
                )
            })?;

        if __info.proposalDeadlineTimestamp == 0
            || __info.proposedTimestamp == 0
            || __info.voteActivationTimestamp == 0
            || __info.voteDeadlineTimestamp == 0
        {
            return Ok(
                actix_web::HttpResponse::BadRequest().json(
                    serde_json::json!({
                        "status": false,
                        "message": "invalid proposal id",
                    })
                )
            );
        }

        __info
    }};
    // Optional arm: custom error mapper (you can still return your own JSON error)
    ($governance:expr, $proposal_id:expr, $err_mapper:expr) => {{
        let __info = $governance
            .get_proposal_timing_info($proposal_id)
            .await
            .map_err($err_mapper)?;

        if __info.proposalDeadlineTimestamp == 0
            || __info.proposedTimestamp == 0
            || __info.voteActivationTimestamp == 0
            || __info.voteDeadlineTimestamp == 0
        {
            return Ok(
                actix_web::HttpResponse::BadRequest().json(
                    serde_json::json!({
                        "status": false,
                        "message": "invalid proposal id",
                    })
                )
            );
        }

        __info
    }};
}

sol! {
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct ProposalHash {
        bytes32 proposal_id;
    }

}

#[derive(ToSchema)]
struct ProposalHashPlaceHolder {
    #[allow(unused)]
    proposal_id: String,
}

#[derive(ToSchema, Serialize, Deserialize)]
struct SecretLoadPlaceholder {
    #[allow(unused)]
    secret: String,
}

#[utoipa::path(
    get,
    path = "/v1/hello",
    responses(
        (status = 200, description = "Hi"),
    ),
    tag = "Hi..."
)]
async fn hello_handler() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "message": "Hi!. This is governance enclave",
    })))
}

#[utoipa::path(
    get,
    path = "/v1/is_config_loaded",
    responses(
        (status = 200, description = "Checks if config is loaded"),
    ),
    tag = "Config"
)]
async fn is_config_loaded() -> actix_web::Result<HttpResponse> {
    let is_loaded = config::if_config_exists().await.map_err(json_error)?;
    if is_loaded {
        Ok(HttpResponse::Ok().json(json!({
            "status": true,
            "message": "Config is loaded",
        })))
    } else {
        Ok(HttpResponse::Ok().json(json!({
            "status": false,
            "message": "Config is not loaded",
        })))
    }
}

#[utoipa::path(
    post,
    path = "/v1/status",
    request_body = ProposalHashPlaceHolder,
    responses(
        (status = 200, description = "Return proposal voting result"),
    ),
    tag = "Manual Compute"
)]
async fn status<K: KMS + Send + Sync>(
    payload: web::Json<ProposalHash>,
    vote_registry: Data<VoteRegistry>,
    kms: Data<K>,
) -> actix_web::Result<impl Responder> {
    let proposal_id = payload.proposal_id;

    // 1) build governance client
    let governance = config::get_governance::<Ethereum>().map_err(json_error)?;

    let governance_enclave = config::get_governance_enclave::<Ethereum>().map_err(json_error)?;

    // 2) try to fetch existing factory; if missing, create it
    let factory = match vote_registry
        .get_factory(&proposal_id)
        .map_err(json_error)?
    {
        Some(f) => f,
        None => {
            let pti = governance
                .get_proposal_timing_info(proposal_id)
                .await
                .map_err(json_error)?;
            vote_registry
                .create_factory(proposal_id, pti)
                .map_err(json_error)?
        }
    };

    let proposal_time_info = fetch_and_check_proposal_time_info!(governance, proposal_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(json_error)?
        .as_secs();

    // If we're still before the vote deadline, voting is in progress
    if U256::from(now) < proposal_time_info.voteDeadlineTimestamp {
        return Ok(HttpResponse::Ok().json(json!({
            "message": "voting in progress",
            "in_progress": true,
            "now": now.to_string(),
            "voteDeadlineTimestamp": proposal_time_info.voteDeadlineTimestamp.to_string()
        })));
    }

    let vote_parser = VoteParse::new(governance.clone(), governance_enclave.clone());
    let sk = kms
        .get_proposal_secret_key(proposal_id)
        .await
        .map_err(json_error)?;

    let factory_clone = factory.clone();
    {
        vote_parser
            .parse_votes(proposal_id, factory_clone, sk)
            .await
            .map_err(|e| json_error(format!("mutex poisoned: {e}")))?;

        drop(vote_parser);
    }

    let vote_factory = factory
        .lock()
        .map_err(|e| json_error(format!("mutex poisoned: {e}")))?;

    let computed_contract_config_hash = governance
        .compute_contract_data_hash(proposal_id)
        .await
        .map_err(|e| json_error(format!("compute contract hashes error: {e}")))?;

    let nearest_block_on_gov_chain = governance
        .get_accurate_proposal_creation_block_number(proposal_id)
        .await
        .map_err(|e| json_error(format!("vote result generation error: {e}")))?;

    let computed_network_hash = governance_enclave
        .compute_network_hash(nearest_block_on_gov_chain)
        .await
        .map_err(|e| json_error(format!("fetch proposal hashes error: {e}")))?;

    let contract_data_preimage = ContractDataPreimage {
        governance_contract_address: governance.get_address(),
        proposed_timestamp: proposal_time_info.proposedTimestamp,
        contract_config_hash: computed_contract_config_hash,
        network_hash: computed_network_hash,
        vote_hash: vote_factory.vote_hash(),
    };

    let image_id = fetch_image_id()
        .await
        .map_err(|e| json_error(format!("failed image id fetch: {e}")))?;

    let voting_aggregator = vote_result::VoteAggregator::new(
        proposal_id,
        image_id,
        vote_factory.weighted_votes(),
        kms.clone().into_inner(),
        contract_data_preimage,
    );

    let submit_result_input_params = voting_aggregator
        .get_submit_result_input_params()
        .await
        .map_err(|e| json_error(format!("vote result generation error: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "in_progress": false,
            "submit_result_input_params": submit_result_input_params,
            "vote_snapshot": vote_factory.weighted_votes(),
            "vote_hash": vote_factory.vote_hash(),
            "raw_votes": vote_factory.votes()
        }
    )))
}

#[utoipa::path(
    post,
    path = "/v1/proposal_encryption_key",
    request_body = ProposalHashPlaceHolder,
    responses(
        (status = 200, description = "Return proposal voting result"),
    ),
    tag = "Deprecated"
)]
async fn proposal_encryption_key<K: KMS + Send + Sync>(
    payload: web::Json<ProposalHash>,
    kms: Data<K>,
) -> actix_web::Result<impl Responder> {
    let proposal_id = payload.proposal_id;

    let governance = config::get_governance::<Ethereum>().map_err(json_error)?;

    fetch_and_check_proposal_time_info!(governance, proposal_id);

    let pk: EncryptionPublicKey = kms
        .get_proposal_public_key(proposal_id)
        .await
        .map_err(|e| json_error(format!("proposal key error: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "proposal_id": proposal_id,
            "encryption_key": format!("0x{}", hex::encode(pk.serialize())),
            "encryption_key_compressed": format!("0x{}", hex::encode(pk.serialize_compressed()))
        }
    )))
}

#[utoipa::path(
    get,
    path = "/v1/encryption_key",
    responses(
        (status = 200, description = "Return proposal voting result"),
    ),
    tag = "Deprecated"
)]
async fn encryption_key<K: KMS + Send + Sync>(kms: Data<K>) -> actix_web::Result<impl Responder> {
    let pk: EncryptionPublicKey = kms
        .get_persistent_encryption_public_key()
        .await
        .map_err(|e| json_error(format!("encryption key error: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "encryption_key": format!("0x{}", hex::encode(pk.serialize())),
            "encryption_key_compressed": format!("0x{}", hex::encode(pk.serialize_compressed()))
        }
    )))
}

#[utoipa::path(
    get,
    path = "/v1/kms_root_server_key",
    responses(
        (status = 200, description = "Return KMS root server key"),
    ),
    tag = "Deprecated"
)]
async fn kms_root_server_key<K: KMS + Send + Sync>(
    kms: Data<K>,
) -> actix_web::Result<impl Responder> {
    let pk = kms
        .get_persistent_public_key()
        .await
        .map_err(|e| json_error(format!("signing key error: {e}")))?;

    let address = kms
        .get_persistant_signing_address()
        .await
        .map_err(|e| json_error(format!("signing key error: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "signing_public_key": format!("0x{}", hex::encode(pk)),
            "address": address,
            "version": "bullseye"
        }
    )))
}

#[utoipa::path(
    get,
    path = "/v1/image_id",
    responses(
        (status = 200, description = "Return image id of the enclave"),
    ),
    tag = "Manual Compute"
)]
async fn image_id() -> actix_web::Result<impl Responder> {
    let image_id = fetch_image_id()
        .await
        .map_err(|e| json_error(format!("failed image id fetch: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "image_id": format!("0x{}", hex::encode(image_id))
        }
    )))
}

#[utoipa::path(
    get,
    path = "/v1/contracts",
    responses(
        (status = 200, description = "Return contracts that are being used"),
    ),
    tag = "Config"
)]
async fn contracts() -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(json!(
        {
            "GOVERNANCE": config::GOVERNANCE,
            "GOVERNANCE_ENCLAVE": config::GOVERNANCE_ENCLAVE
        }
    )))
}

#[utoipa::path(
    post,
    path = "/v1/load_config",
    request_body = SecretLoadPlaceholder,
    responses(
        (status = 200, description = "Load Config"),
    ),
    tag = "Config"
)]
async fn load_config<K: KMS + Send + Sync>(
    payload: web::Json<SecretLoadPlaceholder>,
    kms: Data<K>,
) -> actix_web::Result<impl Responder> {
    let secret_hex = payload.0.secret;
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| json_error(format!("unable to decode secret hex: {e}")))?;

    create_config(kms.into_inner(), &secret_bytes)
        .await
        .map_err(|e| json_error(format!("load config issue: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "status": true
        }
    )))
}

#[utoipa::path(
    delete,
    path = "/v1/delete_config",
    responses(
        (status = 200, description = "DeleteConfig"),
    ),
    tag = "Config"
)]
async fn delete_config() -> actix_web::Result<impl Responder> {
    delete_config_file()
        .await
        .map_err(|e| json_error(format!("Failed to delete config: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "status": true
        }
    )))
}

#[utoipa::path(
    post,
    path = "/v1/proposal_hashes",
    request_body = ProposalHashPlaceHolder,
    responses(
        (status = 200, description = "Return proposal hashes"),
    ),
    tag = "Compare",
    description = "Compare the offchain and onchain hashes"
)]
async fn proposal_hashes<K: KMS + Send + Sync>(
    payload: web::Json<ProposalHash>,
    vote_registry: Data<VoteRegistry>,
    kms: Data<K>,
) -> actix_web::Result<impl Responder> {
    let proposal_id = payload.proposal_id;

    let governance = config::get_governance::<Ethereum>().map_err(json_error)?;

    let governance_enclave = config::get_governance_enclave::<Ethereum>().map_err(json_error)?;

    fetch_and_check_proposal_time_info!(governance, proposal_id);

    let nearest_block_on_gov_chain = governance
        .get_accurate_proposal_creation_block_number(proposal_id)
        .await
        .map_err(|e| json_error(format!("vote result generation error: {e}")))?;

    let computed_contract_config_hash = governance
        .compute_contract_data_hash(proposal_id)
        .await
        .map_err(|e| json_error(format!("compute contract hashes error: {e}")))?;

    #[allow(deprecated)]
    let proposal_hashses = governance
        .get_proposal_hash(proposal_id)
        .await
        .map_err(|e| json_error(format!("get contract hashes error: {e}")))?;

    let computed_network_hash = governance_enclave
        .compute_network_hash(nearest_block_on_gov_chain)
        .await
        .map_err(|e| json_error(format!("fetch proposal hashes error: {e}")))?;

    #[allow(deprecated)]
    let vote_hash_on_contract = governance
        .get_vote_hash_from_contract(proposal_id)
        .await
        .map_err(|e| json_error(format!("vote hash error: {e}")))?;

    let factory = match vote_registry
        .get_factory(&proposal_id)
        .map_err(json_error)?
    {
        Some(f) => f,
        None => {
            let pti = governance
                .get_proposal_timing_info(proposal_id)
                .await
                .map_err(json_error)?;
            vote_registry
                .create_factory(proposal_id, pti)
                .map_err(json_error)?
        }
    };

    let vote_parser = VoteParse::new(governance.clone(), governance_enclave.clone());
    let sk = kms
        .get_proposal_secret_key(proposal_id)
        .await
        .map_err(json_error)?;

    let factory_clone = factory.clone();
    {
        vote_parser
            .parse_votes(proposal_id, factory_clone, sk)
            .await
            .map_err(|e| json_error(format!("mutex poisoned: {e}")))?;

        drop(vote_parser);
    }

    let vote_factory = factory
        .lock()
        .map_err(|e| json_error(format!("mutex poisoned: {e}")))?;

    Ok(HttpResponse::Ok().json(json!({
            "config_hash": {
                "actual": proposal_hashses._2,
                "computed": computed_contract_config_hash
            },
            "network_hash": {
                "computed": proposal_hashses._1,
                "actual": computed_network_hash
            },
            "vote_hash": {
                "computed": vote_factory.vote_hash(),
                "actual": vote_hash_on_contract
            }
        }
    )))
}

pub fn get_scope<K: KMS + Send + Sync + 'static>() -> actix_web::Scope {
    web::scope("/v1")
        .route("/hello", web::get().to(hello_handler))
        .route("/is_config_loaded", web::get().to(is_config_loaded))
        .route("/delete_config", web::delete().to(delete_config))
        .route("/image_id", web::get().to(image_id))
        .route("/encryption_key", web::get().to(encryption_key::<K>))
        .route("/status", web::post().to(status::<K>))
        .route("/load_config", web::post().to(load_config::<K>))
        .route(
            "/proposal_encryption_key",
            web::post().to(proposal_encryption_key::<K>),
        )
        .route("/proposal_hashes", web::post().to(proposal_hashes::<K>))
        .route(
            "/kms_root_server_key",
            web::get().to(kms_root_server_key::<K>),
        )
        .route("/contracts", web::get().to(contracts))
}

#[cfg(feature = "contract_image_id_source")]
pub async fn fetch_image_id() -> Result<B256> {
    let governance_enclave = config::get_governance_enclave::<Ethereum>()?;
    let chain_rpc_url = create_gov_chain_rpc_url()?;
    let nearest_block_on_gov_chain = latest_block::<Ethereum>(&chain_rpc_url).await?;

    let image_id = ContractAttestationSource::new(governance_enclave)
        .image_id(nearest_block_on_gov_chain)
        .await?;

    Ok(image_id)
}

#[cfg(not(feature = "contract_image_id_source"))]
pub async fn fetch_image_id() -> Result<B256> {
    // block number is irrelevant here
    let image_id = EnclaveAttestationSource::new("127.0.0.1", "1301")
        .image_id(0)
        .await?;

    Ok(image_id)
}

use actix_web::{error::InternalError, http::StatusCode};

fn json_error<E: std::fmt::Display>(err: E) -> actix_web::Error {
    let body = json!({
        "status": false,
        "message": format!("{err}")
    });

    // IMPORTANT: use 400 instead of 500
    InternalError::new(body, StatusCode::BAD_REQUEST).into()
}
