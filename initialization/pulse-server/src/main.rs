use std::convert::Infallible;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioIo;
use oyster::scallop::new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b;
use tokio::fs::read;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

async fn hello(_req: Request<Incoming>) -> Result<Response<String>, Infallible> {
    Ok(Response::new("Hello World!".into()))
}

async fn handler(stream: TcpStream, secret: [u8; 32]) -> Result<()> {
    let stream =
        new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(stream, &secret, None::<()>, None::<()>)
            .await
            .context("failed to wrap stream with scallop")?;
    let stream = TokioIo::new(stream);

    if let Err(http_err) = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(stream, service_fn(hello))
        .await
    {
        eprintln!("Error while serving HTTP connection: {}", http_err);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let secret = read("/app/id.sec")
        .await
        .context("failed to read secret")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("invalid size, expected 32, got {}", v.len()))
        .context("invalid secret")?;

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .context("failed to bind listener")?;

    loop {
        let (stream, _) = listener.accept().await?;
        let res = handler(stream, secret).await;

        // exit after first successful transfer
        if res.is_ok() {
            break;
        }
    }

    Ok(())
}
