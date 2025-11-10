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
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

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

    let proposal_time_info = governance
        .get_proposal_timing_info(proposal_id)
        .await
        .map_err(error::ErrorInternalServerError)?;

    if proposal_time_info.proposalDeadlineTimestamp == 0
        || proposal_time_info.proposedTimestamp == 0
        || proposal_time_info.voteActivationTimestamp == 0
        || proposal_time_info.voteDeadlineTimestamp == 0
    {
        return Ok(HttpResponse::BadRequest().json(json!({"message":"invalid proposal id"})));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error::ErrorInternalServerError)?
        .as_secs();

    // If we're still before the vote deadline, voting is in progress
    if U256::from(now) < proposal_time_info.voteDeadlineTimestamp {
        return Ok(HttpResponse::Ok().json(json!({
            "message": "voting in progress",
            "now": now.to_string(),
            "voteDeadlineTimestamp": proposal_time_info.voteDeadlineTimestamp.to_string()
        })));
    }

    let vote_parser = VoteParse::new(governance.clone());
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

    let governance_enclave =
        config::get_governance_enclave::<Ethereum>().map_err(error::ErrorInternalServerError)?;

    let proposal_hashes = governance
        .get_proposal_hash(proposal_id)
        .await
        .map_err(|e| {
            error::ErrorInternalServerError(format!("fetch proposal hashes error: {e}"))
        })?;

    let contract_data_preimage = ContractDataPreimage {
        governance_contract_address: governance.get_address(),
        proposed_timestamp: proposal_time_info.proposedTimestamp,
        contract_config_hash: proposal_hashes._2,
        network_hash: proposal_hashes._1,
        vote_hash: governance
            .get_vote_hash(proposal_id)
            .await
            .map_err(|e| error::ErrorInternalServerError(format!("vote hash error: {e}")))?,
    };

    let voting_aggregator = vote_result::VoteAggregator::new(
        proposal_id,
        governance_enclave
            .get_image_id()
            .await
            .map_err(|e| error::ErrorInternalServerError(format!("failed image id fetch: {e}")))?,
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
            "submit_result_input_params": submit_result_input_params
        }
    )))
}

pub fn get_scope<K: KMS + Send + Sync + 'static>() -> actix_web::Scope {
    web::scope("/v1")
        .route("/hello", web::get().to(hello_handler))
        .route("/status", web::post().to(status::<K>))
}
