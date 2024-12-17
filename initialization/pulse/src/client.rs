use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use oyster::attestation::verify;
use oyster::attestation::AttestationExpectations;
use oyster::scallop::new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b;
use oyster::scallop::ScallopAuthStore;
use tokio::fs::read;
use tokio::net::TcpStream;

struct AuthStore {
    pcrs: [[u8; 48]; 3],
    // in ms
    max_age: usize,
    root_public_key: Vec<u8>,
}

impl ScallopAuthStore for AuthStore {
    fn contains(&self, _key: &[u8; 32]) -> bool {
        false
    }

    fn get(&self, _key: &[u8; 32]) -> Option<&([u8; 48], [u8; 48], [u8; 48])> {
        None
    }

    fn set(&mut self, _key: [u8; 32], _pcrs: ([u8; 48], [u8; 48], [u8; 48])) {}

    fn verify(
        &mut self,
        attestation: &[u8],
        key: &[u8; 32],
    ) -> Option<([u8; 48], [u8; 48], [u8; 48])> {
        let Some(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|x| x.as_millis() as usize)
        else {
            return None;
        };
        let decoded = verify(
            attestation.to_vec(),
            AttestationExpectations {
                pcrs: Some(self.pcrs),
                age: Some((self.max_age, now)),
                root_public_key: Some(self.root_public_key.clone()),
                ..Default::default()
            },
        )
        .ok()?;
        if key != decoded.public_key.as_slice() {
            return None;
        }
        Some(self.pcrs.into())
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// endpoint of the pulse server (<ip:port>)
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// expected pcr0
    #[arg(long)]
    pcr0: String,

    /// expected pcr1
    #[arg(long)]
    pcr1: String,

    /// expected pcr2
    #[arg(long)]
    pcr2: String,

    /// maximum age of attestation (in milliseconds)
    #[arg(short, long)]
    max_age: usize,

    /// expected root public key of the attestation
    #[arg(short, long)]
    root_public_key: String,

    /// path to file whose contents are to be transferred
    #[arg(short, long)]
    filepath: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pcrs: [[u8; 48]; 3] = [
        hex::decode(args.pcr0)?.as_slice().try_into()?,
        hex::decode(args.pcr1)?.as_slice().try_into()?,
        hex::decode(args.pcr2)?.as_slice().try_into()?,
    ];
    let root_public_key: Vec<u8> = hex::decode(args.root_public_key)?;
    let mut auth_store = AuthStore {
        pcrs,
        max_age: args.max_age,
        root_public_key,
    };
    let contents = read(args.filepath).await?;

    let secret = SigningKey::generate(&mut rand::rngs::OsRng).to_bytes();

    let stream = TcpStream::connect(args.endpoint).await?;
    let stream = new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
        stream,
        &secret,
        Some(&mut auth_store),
        None::<()>,
    )
    .await?;

    let stream = TokioIo::new(stream);

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(stream).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Error in connection: {}", e);
        }
    });

    let request = Request::builder()
        .method("GET")
        .body(Full::<Bytes>::new(contents.into()))?;
    let response = request_sender.send_request(request).await?;
    let status = response.status();
    let body = response.collect().await?.to_bytes();

    if status != StatusCode::OK {
        return Err(anyhow!(
            "Error from remote endpoint: {}: {:?}",
            status,
            body
        ));
    }

    println!("Response: {}: {:?}", status, body);

    Ok(())
}
