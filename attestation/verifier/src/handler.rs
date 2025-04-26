use std::error::Error;
use std::num::TryFromIntError;

use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{B256, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{eip712_domain, SolStruct},
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use oyster::attestation::{
    verify as verify_attestation, AttestationError, AttestationExpectations, AWS_ROOT_KEY,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone)]
pub struct AppState {
    pub secp256k1_secret: PrivateKeySigner,
    pub secp256k1_public: [u8; 64],
}

#[derive(Deserialize, Serialize)]
struct RawAttestation {
    attestation: String,
}

#[derive(Deserialize, Serialize)]
struct HexAttestation {
    attestation: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyAttestationResponse {
    pub signature: String,
    pub public_key: String,
    pub image_id: String,
    pub timestamp: usize,
    pub verifier_public_key: String,
}

#[derive(Error)]
pub enum UserError {
    #[error("error while decoding attestation doc from hex")]
    AttestationDecode(#[source] hex::FromHexError),
    #[error("error while verifying attestation")]
    AttestationVerification(#[source] AttestationError),
    #[error("Signature generation failed")]
    SignatureGeneration(#[source] alloy::signers::Error),
    #[error("invalid recovery id")]
    InvalidRecovery(#[source] TryFromIntError),
    #[error("user data too big")]
    UserDataTooBig,
}

impl From<UserError> for (StatusCode, String) {
    fn from(value: UserError) -> Self {
        use UserError::*;
        (
            match &value {
                AttestationDecode(_) => StatusCode::BAD_REQUEST,
                AttestationVerification(_) => StatusCode::UNAUTHORIZED,
                SignatureGeneration(_) => StatusCode::INTERNAL_SERVER_ERROR,
                InvalidRecovery(_) => StatusCode::UNAUTHORIZED,
                UserDataTooBig => StatusCode::BAD_REQUEST,
            },
            format!("{:?}", value),
        )
    }
}

impl std::fmt::Debug for UserError {
    // pretty print like anyhow
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;

        if self.source().is_some() {
            writeln!(f, "\n\nCaused by:")?;
        }

        let mut err: &dyn Error = self;
        loop {
            let Some(source) = err.source() else { break };
            writeln!(f, "\t{}", source)?;

            err = source;
        }

        Ok(())
    }
}

const DOMAIN: Eip712Domain = eip712_domain! {
    name: "marlin.oyster.AttestationVerifier",
    version: "1",
};

sol! {
    struct Attestation {
        bytes enclavePubKey;
        bytes32 imageId;
        uint256 timestampInMilliseconds;
    }
}

fn compute_signature(
    enclave_pubkey: &[u8],
    image_id: B256,
    timestamp: usize,
    signer: &PrivateKeySigner,
) -> Result<[u8; 65], UserError> {
    let attestation = Attestation {
        enclavePubKey: enclave_pubkey.to_owned().into(),
        imageId: image_id,
        timestampInMilliseconds: U256::from(timestamp),
    };
    let hash = attestation.eip712_signing_hash(&DOMAIN);
    let signature = signer
        .sign_hash_sync(&hash)
        .map_err(UserError::SignatureGeneration)?
        .as_bytes();

    Ok(signature)
}

fn verify(
    attestation: &[u8],
    signer: &PrivateKeySigner,
    public: &[u8; 64],
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    let decoded = verify_attestation(
        attestation,
        AttestationExpectations {
            root_public_key: Some(&AWS_ROOT_KEY),
            ..Default::default()
        },
    )
    .map_err(UserError::AttestationVerification)?;

    let signature = compute_signature(
        &decoded.public_key.as_ref(),
        decoded.image_id.into(),
        decoded.timestamp,
        signer,
    )?;

    Ok(VerifyAttestationResponse {
        signature: hex::encode(signature),
        public_key: hex::encode(decoded.public_key),
        image_id: hex::encode(decoded.image_id),
        timestamp: decoded.timestamp,
        verifier_public_key: hex::encode(public),
    }
    .into())
}

pub async fn verify_raw(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    verify(
        &body.to_vec(),
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}

pub async fn verify_hex(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    let attestation = hex::decode(&body).map_err(UserError::AttestationDecode)?;

    verify(
        &attestation,
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}
