use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use libsodium_sys::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519, crypto_sign_keypair,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

pub use oyster::scallop::*;

type Pcrs = [[u8; 48]; 3];

#[derive(Default)]
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

struct Auther {}

impl ScallopAuther for Auther {
    type Error = ();
    async fn new_auth(&mut self) -> Result<Box<[u8]>, ()> {
        Ok(b"good auth".to_owned().into())
    }
}

async fn server_task(key: Key) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = TcpListener::bind("127.0.0.1:21000").await?;
    let mut auth_store = AuthStore::default();
    let mut auther = Auther {};

    loop {
        let (stream, _) = server.accept().await?;

        let mut stream = new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
            stream,
            &key,
            Some(&mut auth_store),
            Some(&mut auther),
        )
        .await?;

        println!("Client key: {:?}", stream.get_remote_static());

        loop {
            let mut buf = [0u8; 1000];
            let len = stream.read(&mut buf).await?;

            if len == 0 {
                break;
            }

            println!("Server: {} bytes: {:?}", len, &buf[0..len]);
        }

        println!("Server done.");
    }
}

async fn client_task(key: Key) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut auth_store = AuthStore::default();
    let mut auther = Auther {};

    loop {
        let stream = TcpStream::connect("127.0.0.1:21000").await?;

        let mut stream = new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
            stream,
            &key,
            Some(&mut auth_store),
            Some(&mut auther),
        )
        .await?;

        println!("Server key: {:?}", stream.get_remote_static());

        stream.write_all(b"Hello!").await?;
        stream.flush().await?;

        sleep(Duration::from_secs(1)).await;

        stream.write_all(b"I").await?;
        stream.flush().await?;

        sleep(Duration::from_secs(1)).await;

        stream.write_all(b"am").await?;
        stream.flush().await?;

        sleep(Duration::from_secs(1)).await;

        stream.write_all(b"scallop.").await?;
        stream.flush().await?;

        sleep(Duration::from_secs(1)).await;

        println!("Client done.");
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
