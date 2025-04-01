use axum::{
    extract::{Query, State},
    http::StatusCode, response::IntoResponse, Json,
};
use kms_derive_utils::{
    derive_enclave_seed, derive_path_seed, to_ed25519_public, to_ed25519_solana_address,
    to_secp256k1_ethereum_address, to_secp256k1_public, to_x25519_public,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, Message};
use secp256k1::ecdsa::Signature;
use crate::AppState;

#[derive(Deserialize)]
pub struct Params {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    user_data: String,
    path: String,
}

impl Params {
    fn derive_path_seed(&self, seed: [u8; 64]) -> Option<[u8; 64]> {
        let Ok(pcr0) = hex::decode(&self.pcr0) else {
            return None;
        };
        let Ok(pcr1) = hex::decode(&self.pcr1) else {
            return None;
        };
        let Ok(pcr2) = hex::decode(&self.pcr2) else {
            return None;
        };
        let Ok(user_data) = hex::decode(&self.user_data) else {
            return None;
        };

        let enclave_key = derive_enclave_seed(seed, &pcr0, &pcr1, &pcr2, &user_data);
        let path_key = derive_path_seed(enclave_key, self.path.as_bytes());

        Some(path_key)
    }
}

#[derive(Serialize)]
struct PublicKeyResponse {
    public_key: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct PublicKeySecpResponse {
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct AddressResponse {
    info: String,
    signature: Vec<u8>,
}

// derive public key based on params
pub async fn get_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {

    let public = state.public_key;
    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(public.serialize_uncompressed());
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK, Json(PublicKeyResponse {
        public_key: public.serialize_uncompressed()[1..].try_into().expect("Slice conversion failed"),
        signature: signature.serialize_compact().to_vec(),
    }))
}

// derive public key based on params
pub async fn derive_secp256k1_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, Json(PublicKeySecpResponse{public_key: vec![], signature: vec![]}));
    };
    let public = to_secp256k1_public(path_key);

    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(public);
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK, Json(PublicKeySecpResponse{public_key: public.to_vec(), signature: signature.serialize_compact().to_vec()}))
}

// derive address based on params
pub async fn derive_secp256k1_address_ethereum(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, Json(AddressResponse{info: String::new(), signature: vec![]}));
    };
    let address = to_secp256k1_ethereum_address(path_key);
    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(address.clone());
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK, Json(AddressResponse {
        info: address,
        signature: signature.serialize_compact().to_vec(),
    }))
}

// derive public key based on params
pub async fn derive_ed25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, Json(PublicKeyResponse{public_key:[0; 32],signature: vec![]}));
    };
    let public = to_ed25519_public(path_key);

    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(public);
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK,Json(PublicKeyResponse {
        public_key: public,
        signature: signature.serialize_compact().to_vec(),
    }))
}

// derive address based on params
pub async fn derive_ed25519_address_solana(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, Json(AddressResponse{info: String::new(), signature: vec![]}));
    };
    let address = to_ed25519_solana_address(path_key);
    
    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(address.clone());
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK, Json(AddressResponse {
        info: address,
        signature: signature.serialize_compact().to_vec(),
    }))
}

// derive public key based on params
pub async fn derive_x25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return (StatusCode::BAD_REQUEST, Json(PublicKeyResponse{public_key:[0; 32],signature: vec![]}));
    };
    let public = to_x25519_public(path_key);
    
    let secp = Secp256k1::new();
    let message_hash = Sha256::digest(public);
    let msg = Message::from_digest_slice(&message_hash).expect("Failed to create message");
    let signature = secp.sign_ecdsa(&msg, &state.private_key);

    (StatusCode::OK, Json(PublicKeyResponse {
        public_key: public,
        signature: signature.serialize_compact().to_vec(),
    }))
}

