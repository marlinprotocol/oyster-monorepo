use clap::Parser;
use http_on_vsock_client::vsock_client::vsock_connector;
use hyper::{body::Body, Request, Uri};
use serde_json::json;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// url to query
    #[clap(short, long, value_parser)]
    url: String,

    // owner address
    #[clap(short, long, value_parser)]
    owner_address: String,

    // gas key
    #[clap(short, long, value_parser)]
    gas_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // WARN: Had to do Box::pin to get it to work, vsock_connector is not Unpin for some reason
    let connector = tower::service_fn(|dst: Uri| Box::pin(vsock_connector(dst)));

    // TODO: Poll executor to come up
    let client = hyper::Client::builder().build::<_, Body>(connector);

    let mut resp = client.get(cli.url.clone().try_into()?).await?;
    println!("{:?}", resp);

    // prepare the post request
    let body = json!({
        "owner_address_hex": cli.owner_address.clone(),
    }).to_string();
    let request = Request::post(cli.url.clone()+"immutable-config")
        .header("Content-Type", "application/json")
        .body(Body::from(body))?;
    resp = client.request(request).await?;
    println!("{:?}", resp);
    println!("{:?}", String::from_utf8(hyper::body::to_bytes(resp.into_body()).await?.to_vec())?);

    // set mutable config
    let body = json!({
        "gas_key_hex": cli.gas_key.clone(),
    }).to_string();
    let request = Request::post(cli.url.clone()+"mutable-config")
        .header("Content-Type", "application/json")
        .body(Body::from(body))?;
    resp = client.request(request).await?;
    println!("{:?}", resp);
    println!("{:?}", String::from_utf8(hyper::body::to_bytes(resp.into_body()).await?.to_vec())?);


    // Get the config
    resp = client.get((cli.url.clone() + "executor-details").try_into()?).await?;
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let body_str = String::from_utf8(body_bytes.to_vec())?;
    let json: serde_json::Value = serde_json::from_str(&body_str)?;
    println!("{:?}", json);

    // Start the executor
    resp = client.get((cli.url.clone() + "signed-registration-message").try_into()?).await?;
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let body_str = String::from_utf8(body_bytes.to_vec())?;
    let json: serde_json::Value = serde_json::from_str(&body_str)?;
    println!("{:?}", json);

    Ok(())
}
