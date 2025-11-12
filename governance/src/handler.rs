use crate::{
    config,
    kms::KMS,
    vote_parser::VoteParse,
    vote_registry::VoteRegistry,
    vote_result::{self, ContractDataPreimage},
};
use actix_web::{
    HttpResponse, Responder, error,
    web::{self, Data},
};
use alloy::{network::Ethereum, primitives::U256, sol};
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
    ($governance:expr, $proposal_id:expr) => {{
        let __info = $governance
            .get_proposal_timing_info($proposal_id)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?;

        if __info.proposalDeadlineTimestamp == 0
            || __info.proposedTimestamp == 0
            || __info.voteActivationTimestamp == 0
            || __info.voteDeadlineTimestamp == 0
        {
            return Ok(actix_web::HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "invalid proposal id" })));
        }

        __info
    }};
    // Optional arm: custom error mapper
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
            return Ok(actix_web::HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "invalid proposal id" })));
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
    let governance =
        config::get_governance::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    let governance_enclave =
        config::get_governance_enclave::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    // 2) try to fetch existing factory; if missing, create it
    let factory = match vote_registry
        .get_factory(&proposal_id)
        .map_err(error::ErrorInternalServerError)?
    {
        Some(f) => f,
        None => {
            let pti = governance
                .get_proposal_timing_info(proposal_id)
                .await
                .map_err(error::ErrorInternalServerError)?;
            vote_registry
                .create_factory(proposal_id, pti)
                .map_err(error::ErrorInternalServerError)?
        }
    };

    let proposal_time_info = fetch_and_check_proposal_time_info!(governance, proposal_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error::ErrorInternalServerError)?
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
        .map_err(error::ErrorInternalServerError)?;

    let factory_clone = factory.clone();
    {
        vote_parser
            .parse_votes(proposal_id, factory_clone, sk)
            .await
            .map_err(|e| error::ErrorInternalServerError(format!("mutex poisoned: {e}")))?;

        drop(vote_parser);
    }

    let vote_factory = factory
        .lock()
        .map_err(|e| error::ErrorInternalServerError(format!("mutex poisoned: {e}")))?;

    let computed_contract_config_hash = governance
        .compute_contract_data_hash(proposal_id)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("compute contract hashes error: {e}"))
        })?;

    let nearest_block_on_gov_chain = governance
        .get_proposal_creation_block_number(proposal_id)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("vote result generation error: {e}"))
        })?;

    let computed_network_hash = governance_enclave
        .compute_network_hash(nearest_block_on_gov_chain)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("fetch proposal hashes error: {e}"))
        })?;

    let contract_data_preimage = ContractDataPreimage {
        governance_contract_address: governance.get_address(),
        proposed_timestamp: proposal_time_info.proposedTimestamp,
        contract_config_hash: computed_contract_config_hash,
        network_hash: computed_network_hash,
        vote_hash: vote_factory.vote_hash(),
    };

    let image_id = governance_enclave
        .get_image_id(nearest_block_on_gov_chain)
        .await
        .map_err(|e| error::ErrorInternalServerError(format!("failed image id fetch: {e}")))?;

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
        .map_err(|e| {
            error::ErrorInternalServerError(format!("vote result generation error: {e}"))
        })?;

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

    let governance =
        config::get_governance::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    fetch_and_check_proposal_time_info!(governance, proposal_id);

    let pk: EncryptionPublicKey = kms
        .get_proposal_public_key(proposal_id)
        .await
        .map_err(|e| error::ErrorInternalServerError(format!("proposal key error: {e}")))?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "proposal_id": proposal_id,
            "encryption_key": format!("0x{}", hex::encode(pk.serialize()))
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

    let governance =
        config::get_governance::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    let governance_enclave =
        config::get_governance_enclave::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    fetch_and_check_proposal_time_info!(governance, proposal_id);

    let nearest_block_on_gov_chain = governance
        .get_proposal_creation_block_number(proposal_id)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("vote result generation error: {e}"))
        })?;

    let computed_contract_config_hash = governance
        .compute_contract_data_hash(proposal_id)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("compute contract hashes error: {e}"))
        })?;

    #[allow(deprecated)]
    let proposal_hashses = governance
        .get_proposal_hash(proposal_id)
        .await
        .map_err(|e| error::ErrorInternalServerError(format!("get contract hashes error: {e}")))?;

    let computed_network_hash = governance_enclave
        .compute_network_hash(nearest_block_on_gov_chain)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("fetch proposal hashes error: {e}"))
        })?;

    #[allow(deprecated)]
    let vote_hash_on_contract = governance
        .get_vote_hash_from_contract(proposal_id)
        .await
        .map_err(|e| error::ErrorInternalServerError(format!("vote hash error: {e}")))?;

    let factory = match vote_registry
        .get_factory(&proposal_id)
        .map_err(error::ErrorInternalServerError)?
    {
        Some(f) => f,
        None => {
            let pti = governance
                .get_proposal_timing_info(proposal_id)
                .await
                .map_err(error::ErrorInternalServerError)?;
            vote_registry
                .create_factory(proposal_id, pti)
                .map_err(error::ErrorInternalServerError)?
        }
    };

    let vote_parser = VoteParse::new(governance.clone(), governance_enclave.clone());
    let sk = kms
        .get_proposal_secret_key(proposal_id)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let factory_clone = factory.clone();
    {
        vote_parser
            .parse_votes(proposal_id, factory_clone, sk)
            .await
            .map_err(|e| error::ErrorInternalServerError(format!("mutex poisoned: {e}")))?;

        drop(vote_parser);
    }

    let vote_factory = factory
        .lock()
        .map_err(|e| error::ErrorInternalServerError(format!("mutex poisoned: {e}")))?;

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
        .route("/status", web::post().to(status::<K>))
        .route(
            "/proposal_encryption_key",
            web::post().to(proposal_encryption_key::<K>),
        )
        .route("/proposal_hashes", web::post().to(proposal_hashes::<K>))
}
