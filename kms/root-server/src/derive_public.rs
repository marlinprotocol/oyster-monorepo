use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use kms_derive_utils::{
    derive_enclave_seed, derive_path_seed, to_ed25519_public, to_ed25519_solana_address,
    to_secp256k1_ethereum_address, to_secp256k1_public, to_x25519_public,
};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct Params {
    image_id: String,
    path: String,
}

impl Params {
    fn derive_path_seed(&self, seed: [u8; 64]) -> Option<[u8; 64]> {
        let Ok(image_id) = hex::decode(&self.image_id).and_then(|x| {
            x.try_into()
                .map_err(|_| hex::FromHexError::InvalidStringLength)
        }) else {
            return None;
        };

        let enclave_key = derive_enclave_seed(seed, image_id);
        let path_key = derive_path_seed(enclave_key, self.path.as_bytes());

        Some(path_key)
    }
}

// derive public key based on params
pub async fn derive_secp256k1_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let public = to_secp256k1_public(path_key);

    (StatusCode::OK, public)
}

// derive address based on params
pub async fn derive_secp256k1_address_ethereum(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, String) {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let address = to_secp256k1_ethereum_address(path_key);

    (StatusCode::OK, address)
}

// derive public key based on params
pub async fn derive_ed25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 32]) {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, [0; 32]);
    };
    let public = to_ed25519_public(path_key);

    (StatusCode::OK, public)
}

// derive address based on params
pub async fn derive_ed25519_address_solana(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, String) {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let address = to_ed25519_solana_address(path_key);

    (StatusCode::OK, address)
}

// derive public key based on params
pub async fn derive_x25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 32]) {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, [0; 32]);
    };
    let public = to_x25519_public(path_key);

    (StatusCode::OK, public)
}
