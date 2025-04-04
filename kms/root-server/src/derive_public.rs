use crate::AppState;
use axum::{
    extract::{Query, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};
use kms_derive_utils::{
    derive_enclave_seed, derive_path_seed, to_ed25519_public, to_ed25519_solana_address, to_secp256k1_ethereum_address, to_secp256k1_public, to_secp256k1_secret, to_x25519_public
};
use serde::{Deserialize, Serialize};
use secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use secp256k1::hashes::{sha256, Hash};

const PRIVATE_KEY_PATH: &[u8; 20] = b"oyster.kms.secp256k1";

#[derive(Serialize, Deserialize)]
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

// common function to sign a sha256 message hash using secp256k1
pub fn sign_message(secret_key: [u8; 32], params: Params, message: &[u8]) -> Signature {
    // Serialize Params to JSON bytes.
    let params_bytes = serde_json::to_vec(&params).expect("Failed to serialize params");

    // Combine the original message with the serialized Params.
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(message);
    combined_data.extend_from_slice(&params_bytes);

    let secret_key = SecretKey::from_slice(&secret_key).expect("Invalid private key");    
    let secp = Secp256k1::new();
    let message_hash = sha256::Hash::hash(&combined_data);
    let msg = Message::from_digest(message_hash.to_byte_array());
    secp.sign_ecdsa(&msg, &secret_key)
}

// Common function to generate response with signed data
pub fn generate_signed_response<T: IntoResponse>(status: StatusCode, data: T, signature: Signature) -> impl IntoResponse {
    let mut response = (status, data).into_response();
    response.headers_mut().insert(
        header::HeaderName::from_static("x-kms-signature"),
        HeaderValue::from_str(&hex::encode(signature.serialize_compact())).unwrap(),
    );
    response
}

// derive public key based on params
pub async fn derive_secp256k1_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return generate_signed_response(StatusCode::BAD_REQUEST, [0; 64], Signature::from_compact(&[0; 64]).unwrap());
    };
    let public = to_secp256k1_public(path_key);
    let signature = sign_message(to_secp256k1_secret(derive_path_seed(state.seed, PRIVATE_KEY_PATH)),params , &public);
    generate_signed_response(StatusCode::OK, public, signature)
}

// derive address based on params
pub async fn derive_secp256k1_address_ethereum(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return generate_signed_response(StatusCode::BAD_REQUEST, String::new(), Signature::from_compact(&[0; 64]).unwrap());
    };
    let address = to_secp256k1_ethereum_address(path_key);
    let signature = sign_message(to_secp256k1_secret(derive_path_seed(state.seed, PRIVATE_KEY_PATH)), params,&address.clone().into_bytes());
    generate_signed_response(StatusCode::OK, address, signature)
}

// derive public key based on params
pub async fn derive_ed25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return generate_signed_response(StatusCode::BAD_REQUEST, [0; 32], Signature::from_compact(&[0; 64]).unwrap());
    };
    let public = to_ed25519_public(path_key);
    let signature = sign_message(to_secp256k1_secret(derive_path_seed(state.seed, PRIVATE_KEY_PATH)), params, &public);
    generate_signed_response(StatusCode::OK, public, signature)
}

// derive address based on params
pub async fn derive_ed25519_address_solana(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return generate_signed_response(StatusCode::BAD_REQUEST, String::new(), Signature::from_compact(&[0; 64]).unwrap());
    };
    let address = to_ed25519_solana_address(path_key);
    let signature = sign_message(to_secp256k1_secret(derive_path_seed(state.seed, PRIVATE_KEY_PATH)), params,&address.clone().into_bytes());
    generate_signed_response(StatusCode::OK, address, signature)
}

// derive public key based on params
pub async fn derive_x25519_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    let Some(path_key) = params.derive_path_seed(state.seed) else {
        return generate_signed_response(StatusCode::BAD_REQUEST, [0; 32], Signature::from_compact(&[0; 64]).unwrap());
    };
    let public = to_x25519_public(path_key);
    let signature = sign_message(to_secp256k1_secret(derive_path_seed(state.seed, PRIVATE_KEY_PATH)), params, &public);
    generate_signed_response(StatusCode::OK, public, signature)
}
