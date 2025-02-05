use std::ops::Deref;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::command;
use clap::Parser;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioIo;
use oyster::scallop::new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b;
use oyster::scallop::ScallopAuther;
use tokio::fs::read;
use tokio::fs::write;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

struct Auther {
    url: String,
}

impl ScallopAuther for Auther {
    type Error = reqwest::Error;
    async fn new_auth(&mut self) -> Result<Box<[u8]>, Self::Error> {
        let body = reqwest::get(&self.url).await?.bytes().await?;
        Ok(body.deref().into())
    }
}

async fn handler(
    stream: TcpStream,
    secret: [u8; 32],
    filepath: &str,
    auther: &mut Auther,
) -> Result<()> {
    let stream = new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
        stream,
        &secret,
        None::<()>,
        Some(auther),
    )
    .await
    .context("failed to wrap stream with scallop")?;
    let stream = TokioIo::new(stream);

    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            stream,
            service_fn(|req: Request<Incoming>| async move {
                // store in filepath
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .context("failed to collect body")?
                    .to_bytes();
                write(filepath, body)
                    .await
                    .map(|_| Response::new("success".to_owned()))
                    .context("failed to write to file")
            }),
        )
        .await
        .context("failed to serve conn")
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Auther URL
    #[arg(short, long, default_value = "http://127.0.0.1:1300/attestation/raw")]
    auther_url: String,

    /// Path to file where contents are to be saved
    #[arg(short, long, default_value = "/app/.env")]
    filepath: String,

    /// Path to secret file
    #[arg(short, long, default_value = "/app/id.sec")]
    secret: String,

    /// Address on which server listens for connections
    #[arg(short, long, default_value = "127.0.0.1:1600")]
    listen_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut auther = Auther {
        url: args.auther_url,
    };
    let filepath = args.filepath;

    let secret = read(args.secret)
        .await
        .context("failed to read secret")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("invalid size, expected 32, got {}", v.len()))
        .context("invalid secret")?;

    let listener = TcpListener::bind(args.listen_addr)
        .await
        .context("failed to bind listener")?;

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept connections")?;
        let res = handler(stream, secret, &filepath, &mut auther).await;

        // exit after first successful transfer
        if res.is_ok() {
            break;
        }
    }

    Ok(())
}
