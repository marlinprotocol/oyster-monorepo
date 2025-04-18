use alloy::{primitives::B256, providers::ProviderBuilder, sol};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
};
use kms_derive_utils::derive_enclave_contract_seed;
use oyster::axum::ScallopState;
use serde::Deserialize;
use IKMSVerifiable::IKMSVerifiableInstance;

use crate::{scallop::AuthStoreState, AppState};

sol!(
    #[sol(rpc)]
    interface IKMSVerifiable {
        function oysterKMSVerify(bytes32 _imageId) external returns (bool);
    }
);

#[derive(Deserialize)]
pub struct Params {
    address: String,
}

// derive keys after verifying attestations
pub async fn derive(
    ConnectInfo(scallop_state): ConnectInfo<ScallopState<AuthStoreState>>,
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let Ok(address) = params.address.parse() else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let Ok(rpc) = state.rpc.parse() else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let provider = ProviderBuilder::new().on_http(rpc);
    let contract = IKMSVerifiableInstance::new(address, provider);

    // SAFETY: transport should always have image id associated, safe to unwrap
    let image_id = scallop_state.0.unwrap();

    let Ok(res) = contract.oysterKMSVerify(B256::from(image_id)).call().await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, [0; 64]);
    };

    // error if key is not verified
    if !res._0 {
        return (StatusCode::UNAUTHORIZED, [0; 64]);
    }

    let derived_key = derive_enclave_contract_seed(state.seed, state.chain_id, &params.address);

    (StatusCode::OK, derived_key)
}
