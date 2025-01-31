use std::error::Error;

use axum::{routing::get, Router};
use clap::Parser;

/// http server for handling attestation document requests
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the server (e.g. 127.0.0.1:1300)
    #[arg(short, long)]
    ip_addr: String,

    /// path to public key file (e.g. /app/id.pub)
    #[arg(short, long)]
    pub_key: String,

    /// path to init params file (e.g. /app/init-params)
    #[arg(long)]
    init_params: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // leak in order to get a static slice
    // okay to do since it will get cleaned up on exit
    let pub_key = std::fs::read(cli.pub_key)?.leak::<'static>();
    println!("pub key: {:02x?}", pub_key);

    let init_params = std::fs::read(cli.init_params)
        .unwrap_or(Vec::new())
        .leak::<'static>();

    let app = Router::new()
        .route(
            "/attestation/raw",
            get(|| async { oyster_attestation_server::get_attestation_doc(pub_key, init_params) }),
        )
        .route(
            "/attestation/hex",
            get(|| async {
                oyster_attestation_server::get_hex_attestation_doc(pub_key, init_params)
            }),
        );
    let listener = tokio::net::TcpListener::bind(&cli.ip_addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
