use anyhow::Context;
use anyhow::Result;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let app = Router::new().route("/", get(|| async { "Hello" }));

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .context("failed to bind listener")?;

    axum::serve(listener, app).await.context("serve error")
}
