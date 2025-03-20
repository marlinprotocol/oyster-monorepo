use crate::configs::global::{PINATA_GATEWAY_URL, PINATA_UPLOAD_URL};
use crate::types::StorageProvider;
use anyhow::{anyhow, Context, Result};
use clap::Args;
use reqwest::Client;
use serde_json::Value;
use std::{env, fs, time::Duration};
use tracing::info;

#[derive(Args)]
pub struct UploadArgs {
    /// Path to enclave image file
    #[arg(short, long)]
    file: String,
}

pub async fn upload_enclave_image(args: UploadArgs) -> Result<()> {
    let file_path = &args.file;
    let provider = StorageProvider::Pinata;

    info!("Uploading enclave image with:");
    info!("  File path: {}", file_path);
    info!("  Provider: {}", provider.as_str());

    let file_content = fs::read(file_path).context("Failed to read enclave image file")?;
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .context("Failed to get file name")?
        .to_str()
        .context("Failed to convert file name to string")?;

    let (api_key, secret_key) = (
        env::var("PINATA_API_KEY").context("PINATA_API_KEY not set in environment")?,
        env::var("PINATA_API_SECRET").context("PINATA_API_SECRET not set in environment")?,
    );
    upload_to_pinata(&file_content, file_name, &api_key, &secret_key).await?;
    Ok(())
}

async fn upload_to_pinata(
    content: &[u8],
    filename: &str,
    api_key: &str,
    secret_key: &str,
) -> Result<String> {
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(content.to_vec()).file_name(filename.to_string()),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .post(PINATA_UPLOAD_URL)
        .header("pinata_api_key", api_key)
        .header("pinata_secret_api_key", secret_key)
        .multipart(form)
        .send()
        .await
        .context("Failed to send request to Pinata")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Upload failed: {}",
            response.text().await.unwrap_or_default()
        ));
    }

    let json: Value = response
        .json()
        .await
        .context("Failed to parse Pinata response")?;
    let hash = json["IpfsHash"]
        .as_str()
        .context("Failed to get IPFS hash from response")?;
    let url = format!("{}/{}", PINATA_GATEWAY_URL, hash);
    info!("Successfully uploaded to Pinata: {}", url);
    Ok(url)
}
