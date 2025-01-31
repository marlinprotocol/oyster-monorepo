use anyhow::{anyhow, Context, Result};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use oyster::scallop::new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b;
use tokio::net::TcpStream;

use crate::scallop::{AuthStore, Auther};

pub async fn fetch_randomness(
    auther: Auther,
    auth_store: AuthStore,
    secret: [u8; 32],
    kms_enpdoint: String,
) -> Result<[u8; 64]> {
    // oh how I wish I could use reqwest

    let stream = TcpStream::connect(kms_enpdoint)
        .await
        .context("failed to connect to kms server")?;
    let scallop_stream = new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
        stream,
        &secret,
        Some(auth_store),
        Some(auther),
    )
    .await
    .context("failed to scallop")?;

    let hyper_stream = TokioIo::new(scallop_stream);

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(hyper_stream)
        .await
        .context("failed handshake")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Error in connection: {}", e);
        }
    });

    let request = Request::builder()
        .method("GET")
        .uri("/derive")
        .body("".to_string())
        .context("failed to build request")?;
    let response = request_sender
        .send_request(request)
        .await
        .context("failed to send request")?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!("request error"));
    }
    let randomness: [u8; 64] = response
        .collect()
        .await
        .context("failed to collect body")?
        .to_bytes()
        .as_ref()
        .try_into()
        .context("response is not the right size")?;

    Ok(randomness)
}
