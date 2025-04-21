use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
};
use kms_derive_utils::derive_enclave_seed;
use oyster::axum::ScallopState;

use crate::{scallop::AuthStoreState, AppState};

// derive keys after verifying attestations
pub async fn derive(
    ConnectInfo(scallop_state): ConnectInfo<ScallopState<AuthStoreState>>,
    State(state): State<AppState>,
) -> (StatusCode, [u8; 64]) {
    // safe to unwrap since the server should always have an authstore
    let image_id = scallop_state.0.unwrap();

    let derived_key = derive_enclave_seed(state.seed, image_id);

    (StatusCode::OK, derived_key)
}
