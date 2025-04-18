use alloy::{
    hex,
    primitives::keccak256,
    signers::{local::PrivateKeySigner, SignerSync},
};
use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::get, Router};
use clap::Parser;
use kms_derive_utils::{derive_path_seed, to_secp256k1_public, to_x25519_public};
use nucypher_core::{
    encrypt_for_dkg, ferveo::api::DkgPublicKey, AccessControlPolicy, Conditions, ProtocolObject,
    ThresholdMessageKit,
};
use rand::{rngs::OsRng, TryRngCore};
use tokio::{
    fs::{read, read_to_string},
    net::TcpListener,
};

#[derive(Clone)]
struct AppState {
    signer: PrivateKeySigner,
    conditions: Conditions,
    dkg_public_key: DkgPublicKey,
}

fn encrypt(
    message: &[u8; 64],
    conditions: &Conditions,
    dkg_public_key: DkgPublicKey,
    auth_signer: PrivateKeySigner,
) -> Result<String> {
    // encrypt
    let (ciphertext, auth_data) =
        encrypt_for_dkg(message, &dkg_public_key, &conditions).context("encrypt failed")?;

    // calculate header hash
    let header_hash = keccak256(
        bincode::serde::encode_to_vec(
            &ciphertext.header().context("failed to get header")?,
            bincode::config::legacy(),
        )
        .context("failed to serialize header")?,
    );

    // sign the header hash
    let authorization = auth_signer
        .sign_message_sync(header_hash.as_slice())
        .context("signing failed")?
        .as_bytes()
        .into();

    // create access control policy
    let acp = AccessControlPolicy {
        auth_data,
        authorization,
    };

    // create message kit
    let message_kit = ThresholdMessageKit { ciphertext, acp };

    // message bytes
    let mut message_bytes = message_kit.to_bytes().to_vec();

    // add derived secp256k1 public key to the message
    // expected to be used for signing public KMS responses
    message_bytes.extend_from_slice(&to_secp256k1_public(derive_path_seed(
        *message,
        b"oyster.kms.secp256k1",
    )));
    // add derived x25519 public key to the message
    // expected to be used for scallop auth
    message_bytes.extend_from_slice(&to_x25519_public(derive_path_seed(
        *message,
        b"oyster.kms.x25519",
    )));

    // message signature
    let signature = auth_signer
        .sign_message_sync(&message_bytes)
        .context("signing failed")?
        .as_bytes();

    message_bytes.extend_from_slice(&signature);

    Ok(hex::encode(message_bytes))
}

// generate new seed and encrypt it against the DKG key
async fn generate(State(state): State<AppState>) -> (StatusCode, String) {
    // generate seed
    let mut seed = [0u8; 64];
    if OsRng.try_fill_bytes(seed.as_mut()).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to generate seed\n".into(),
        );
    };

    // generate encrypted message
    let Ok(encrypted) = encrypt(&seed, &state.conditions, state.dkg_public_key, state.signer)
    else {
        // NOTE: Explicitly do not do anything with the error message
        // lest it leaks something about the encryption process
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encrypt\n".into(),
        );
    };

    (StatusCode::OK, encrypted)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// DKG listening address
    #[arg(long, default_value = "0.0.0.0:1100")]
    listen_addr: String,

    /// Path to file with private key signer
    #[arg(long, default_value = "/app/secp256k1.sec")]
    signer: String,

    /// File path for the condition for the seed
    #[arg(long)]
    condition_path: String,

    /// DKG ceremony public key
    #[arg(long)]
    dkg_public_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let signer = PrivateKeySigner::from_slice(
        &read(&args.signer)
            .await
            .context("failed to read signer file")?,
    )
    .context("failed to create signer")?;

    let dkg_public_key = DkgPublicKey::from_bytes(
        &hex::decode(args.dkg_public_key).context("failed to decode dkg public key")?,
    )
    .context("failed to parse dkg public key")?;

    let condition = read_to_string(args.condition_path)
        .await
        .context("failed to read condition file")?;
    let conditions = Conditions::new(&condition);

    let app_state = AppState {
        conditions,
        dkg_public_key,
        signer,
    };

    let app = Router::new()
        .route("/generate", get(generate))
        .with_state(app_state);

    let listener = TcpListener::bind(&args.listen_addr)
        .await
        .context("failed to bind listener")?;

    println!("Listening on {}", args.listen_addr);
    axum::serve(listener, app).await.context("failed to serve")
}
