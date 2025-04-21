use alloy::signers::{
    k256::sha2::{Digest, Sha256},
    SignerSync,
};
use axum::{
    body::to_bytes,
    extract::{Query, Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
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

pub async fn signing_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // store the uri
    let uri = req.uri().clone();

    // run the request
    let mut res = next.run(req).await;

    // only sign successful responses
    if res.status().is_success() {
        // decompose response
        let (mut parts, body) = res.into_parts();

        // extract body bytes
        let body_bytes = match to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(uri.to_string());
        hasher.update(&body_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        let signature = match state.signing_key.sign_hash_sync(&digest.into()) {
            Ok(sig) => sig,
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        let signature_hex = hex::encode(signature.as_bytes());

        match HeaderValue::from_str(&signature_hex) {
            Ok(header_value) => {
                parts.headers.insert(
                    HeaderName::from_static("x-marlin-kms-signature"),
                    header_value,
                );
            }
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        // reconstruct the response
        res = Response::from_parts(parts, axum::body::Body::from(body_bytes));
    }

    Ok(res)
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
