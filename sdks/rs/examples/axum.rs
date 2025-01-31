// Axum based example for the scallop transport

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::{routing::get, Router};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use libsodium_sys::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519, crypto_sign_keypair,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

pub use oyster::axum::*;
pub use oyster::scallop::*;

type Pcrs = [[u8; 48]; 3];

#[derive(Default, Clone)]
struct AuthStore {
    store: HashMap<Key, Pcrs>,
}

impl ScallopAuthStore for AuthStore {
    type State = Pcrs;

    fn contains(&mut self, key: &Key) -> ContainsResponse<Pcrs> {
        if let Some(pcrs) = self.store.get(key) {
            ContainsResponse::Approved(pcrs.to_owned())
        } else {
            ContainsResponse::NotFound
        }
    }

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Pcrs> {
        if attestation == b"good auth" {
            self.store.insert(key, [[1u8; 48], [2u8; 48], [3u8; 48]]);
            Some([[1u8; 48], [2u8; 48], [3u8; 48]])
        } else {
            None
        }
    }
}

#[derive(Clone)]
struct Auther {}

impl ScallopAuther for Auther {
    type Error = ();
    async fn new_auth(&mut self) -> Result<Box<[u8]>, ()> {
        Ok(b"good auth".to_owned().into())
    }
}

async fn hello(ConnectInfo(info): ConnectInfo<ScallopState<Pcrs>>) -> &'static str {
    println!("Pcrs: {:?}", info.0);
    "Hello World!"
}

async fn welcome() -> &'static str {
    "Welcome!"
}

async fn server_task(key: Key) -> Result<(), Box<dyn Error + Send + Sync>> {
    let auth_store = AuthStore::default();
    let auther = Auther {};

    let app = Router::new()
        .route("/hello", get(hello))
        .route("/welcome", get(welcome));

    let tcp_listener = TcpListener::bind("127.0.0.1:21000").await?;

    let server = ScallopListener {
        listener: tcp_listener,
        secret: key,
        auth_store,
        auther,
    };

    Ok(axum::serve(
        server,
        app.into_make_service_with_connect_info::<ScallopState<Pcrs>>(),
    )
    .await?)
}

async fn client_task(key: Key) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut auth_store = AuthStore::default();
    let mut auther = Auther {};

    loop {
        let stream = TcpStream::connect("127.0.0.1:21000").await?;

        let stream = new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
            stream,
            &key,
            Some(&mut auth_store),
            Some(&mut auther),
        )
        .await?;

        println!("Server key: {:?}", stream.get_remote_static());

        let stream = TokioIo::new(stream);

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(stream).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });

        let request = Request::builder()
            .method("GET")
            .uri("/hello")
            .body(Empty::<Bytes>::new())?;
        let response = request_sender.send_request(request).await?;
        assert!(response.status() == StatusCode::OK);
        println!("{:?}", response.collect().await?.to_bytes());

        request_sender.ready().await?;
        let request = Request::builder()
            .method("GET")
            .uri("/welcome")
            .body(Empty::<Bytes>::new())?;
        let response = request_sender.send_request(request).await?;
        assert!(response.status() == StatusCode::OK);
        println!("{:?}", response.collect().await?.to_bytes());

        sleep(Duration::from_secs(5)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sign_pk = [0u8; 32];
    let mut sign_sk = [0u8; 64];
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 32];
    unsafe { crypto_sign_keypair(sign_pk.as_mut_ptr(), sign_sk.as_mut_ptr()) };
    unsafe { crypto_sign_ed25519_pk_to_curve25519(pk.as_mut_ptr(), sign_pk.as_ptr()) };
    unsafe { crypto_sign_ed25519_sk_to_curve25519(sk.as_mut_ptr(), sign_sk.as_ptr()) };

    tokio::spawn(server_task(sk));

    sleep(Duration::from_secs(5)).await;
    client_task(sk).await?;

    Ok(())
}
