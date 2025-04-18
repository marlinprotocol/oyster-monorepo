mod handler;

use std::fs;

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use axum::{routing::post, serve, Router};
use clap::Parser;
use handler::{verify_hex, verify_raw, AppState};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// path to secp256k1 private key file (e.g. /app/secp256k1.sec)
    #[arg(long)]
    secp256k1_secret: String,

    /// path to secp256k1 public key file (e.g. /app/secp256k1.pub)
    #[arg(long)]
    secp256k1_public: String,

    /// server ip (e.g. 127.0.0.1)
    #[arg(short, long)]
    ip: String,

    /// server port (e.g. 1400)
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let secp256k1_secret = fs::read(cli.secp256k1_secret.clone()).with_context(|| {
        format!(
            "Failed to read secp256k1_secret from {}",
            cli.secp256k1_secret
        )
    })?;
    let secp256k1_secret = PrivateKeySigner::from_slice(&secp256k1_secret)
        .context("unable to decode secp256k1_secret key from slice")?;

    let secp256k1_public = fs::read(cli.secp256k1_public.clone()).with_context(|| {
        format!(
            "Failed to read secp256k1_public from {}",
            cli.secp256k1_public
        )
    })?;
    let secp256k1_public: [u8; 64] = secp256k1_public
        .as_slice()
        .try_into()
        .context("invalid public key length")?;

    let app = Router::new()
        .route("/verify/raw", post(verify_raw))
        .route("/verify/hex", post(verify_hex))
        .with_state(AppState {
            secp256k1_secret,
            secp256k1_public,
        });
    let listener = tokio::net::TcpListener::bind((cli.ip.as_str(), cli.port))
        .await
        .context("failed to bind listener")?;

    println!("api server running at {}:{}", cli.ip, cli.port);

    serve(listener, app)
        .await
        .context("error while running server")
}

#[cfg(test)]
mod tests {
    use alloy::signers::local::PrivateKeySigner;
    use axum::{
        http::{Method, Request, StatusCode},
        routing::post,
        Router,
    };
    use http_body_util::{BodyExt, Full};
    use tower::ServiceExt;

    use crate::handler::{verify_hex, verify_raw, AppState, VerifyAttestationResponse};

    #[tokio::test]
    async fn test_raw_attestation() {
        let secp256k1_secret = std::fs::read("./src/test/secp256k1.sec").unwrap();
        let secp256k1_public = std::fs::read("./src/test/secp256k1.pub").unwrap();

        let secp256k1_secret = PrivateKeySigner::from_slice(&secp256k1_secret).unwrap();
        let secp256k1_public: [u8; 64] = secp256k1_public.try_into().unwrap();

        let attestation = std::fs::read("./src/test/attestation.bin").unwrap();

        let app = Router::new()
            .route("/verify/raw", post(verify_raw))
            .route("/verify/hex", post(verify_hex))
            .with_state(AppState {
                secp256k1_secret,
                secp256k1_public,
            });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify/raw")
                    .header("Content-Type", "application/octet-stream")
                    .body(Full::new(attestation.into()))
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to make request");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("failed to collect response")
            .to_bytes();
        let parsed: VerifyAttestationResponse =
            serde_json::from_slice(&body).expect("failed to parse response");

        assert_eq!(parsed.signature, "1901d2f64fd27ca9dd7240e6e3782dd989f824942fa050bb8f5dee81d31a70c438b41b2a322d4ffe079320da9259bb4eb45366c643911b20761b2f39c49477ac1b");
        assert_eq!(parsed.public_key, "57febcf9e7f5081d3d24182817df526a1c9c3df7e46b64613acd13f9aa53b81de888a8562ba7b4a0e42c48d24d7e444ffcba311ceddb5068eca2ea899379ab50");
        assert_eq!(
            parsed.image_id,
            "66108020995009b982f24f929900dc974a9a610d6d5a5b9b29209c1bc5154a21"
        );
        assert_eq!(parsed.verifier_public_key, hex::encode(secp256k1_public));
        assert_eq!(parsed.timestamp, 1723012689640);
    }

    #[tokio::test]
    async fn test_hex_attestation() {
        let secp256k1_secret = std::fs::read("./src/test/secp256k1.sec").unwrap();
        let secp256k1_public = std::fs::read("./src/test/secp256k1.pub").unwrap();

        let secp256k1_secret = PrivateKeySigner::from_slice(&secp256k1_secret).unwrap();
        let secp256k1_public: [u8; 64] = secp256k1_public.try_into().unwrap();

        let attestation = std::fs::read("./src/test/attestation.hex").unwrap();

        let app = Router::new()
            .route("/verify/raw", post(verify_raw))
            .route("/verify/hex", post(verify_hex))
            .with_state(AppState {
                secp256k1_secret,
                secp256k1_public,
            });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify/hex")
                    .header("Content-Type", "text/plain")
                    .body(Full::new(attestation.into()))
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to make request");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("failed to collect response")
            .to_bytes();
        let parsed: VerifyAttestationResponse =
            serde_json::from_slice(&body).expect("failed to parse response");

        assert_eq!(parsed.signature, "86ff271ec63c8e8f7010b1edaa70d75f1ca88bdda66463a7cd2a237a53369e20385ad493e37760a017663b4a49c9329b02f91559eabfb7164e8e48d57de760791b");
        assert_eq!(parsed.public_key, "57febcf9e7f5081d3d24182817df526a1c9c3df7e46b64613acd13f9aa53b81de888a8562ba7b4a0e42c48d24d7e444ffcba311ceddb5068eca2ea899379ab50");
        assert_eq!(
            parsed.image_id,
            "66108020995009b982f24f929900dc974a9a610d6d5a5b9b29209c1bc5154a21"
        );
        assert_eq!(parsed.verifier_public_key, hex::encode(secp256k1_public));
        assert_eq!(parsed.timestamp, 1723012992231);
    }
}
