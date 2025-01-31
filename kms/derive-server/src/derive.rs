use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use kms_derive_utils::{
    derive_path_seed, to_ed25519_secret, to_secp256k1_secret, to_x25519_secret,
};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct Params {
    path: String,
}

// derive keys based on derivation path
pub async fn derive(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let derived_key = derive_path_seed(state.randomness, params.path.as_bytes());

    (StatusCode::OK, derived_key)
}

// derive secp256k1 keys based on derivation path
pub async fn derive_secp256k1(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 32]) {
    let derived_key = derive_path_seed(state.randomness, params.path.as_bytes());
    let secret = to_secp256k1_secret(derived_key);

    (StatusCode::OK, secret)
}

// derive ed25519 keys based on derivation path
pub async fn derive_ed25519(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 32]) {
    let derived_key = derive_path_seed(state.randomness, params.path.as_bytes());
    let secret = to_ed25519_secret(derived_key);

    (StatusCode::OK, secret)
}

// derive x25519 keys based on derivation path
pub async fn derive_x25519(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 32]) {
    let derived_key = derive_path_seed(state.randomness, params.path.as_bytes());
    let secret = to_x25519_secret(derived_key);

    (StatusCode::OK, secret)
}
