use anyhow::{Context, Result};
use clap::Args;
use portpicker::pick_unused_port;
use reqwest;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[derive(Args)]
pub struct DevArgs {
    /// Path to the input file to send to the worker
    #[clap(short, long)]
    input_file: Option<String>,
}

fn cleanup_container(container_id: &str) {
    if let Err(e) = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .arg(container_id)
        .output()
    {
        error!("Failed to cleanup container: {}", e);
    }
}

fn stream_logs(container_id: String) {
    thread::spawn(move || {
        let logs = Command::new("docker")
            .arg("logs")
            .arg("-f")
            .arg(&container_id)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match logs {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to start log streaming: {}", e);
                return;
            }
        };

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Stream stdout
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    info!("{}", line);
                }
            }
        });

        // Stream stderr
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    error!("{}", line);
                }
            }
        });
    });
}

pub async fn run_dev(args: DevArgs) -> Result<()> {
    // Check if worker.js exists in current directory
    let worker_path = std::env::current_dir()?.join("worker.js");
    if !worker_path.exists() {
        anyhow::bail!("worker.js not found in current directory");
    }

    // Check if input file exists if provided
    if let Some(input_path) = &args.input_file {
        if !std::path::Path::new(input_path).exists() {
            anyhow::bail!("Input file '{}' not found", input_path);
        }
    }

    // Get absolute path
    let worker_abs_path = worker_path
        .canonicalize()
        .context("Failed to get absolute path of worker.js")?;

    // Find a free port
    let port = pick_unused_port().context("No free ports available")?;

    info!("Starting development server on port : {}", port);

    let docker_process = Command::new("docker")
        .arg("run")
        .arg("-d")
        .arg("--platform")
        .arg("linux/amd64")
        .arg("-p")
        .arg(format!("{}:8080", port))
        .arg("-v")
        .arg(format!("{}:/app/worker.js", worker_abs_path.display()))
        .arg("sagarparker/serverless_workerd")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Show pull progress on stderr
        .spawn()
        .context("Failed to start docker container")?;

    let output = docker_process
        .wait_with_output()
        .context("Failed to get docker container output")?;

    if !output.status.success() {
        anyhow::bail!("Failed to start docker container");
    }

    let container_id = String::from_utf8(output.stdout)
        .context("Failed to read container ID")?
        .trim()
        .to_string();

    let container_id_clone = container_id.clone();

    // Start log streaming
    stream_logs(container_id.clone());

    ctrlc::set_handler(move || {
        cleanup_container(&container_id_clone);
    })?;

    // Wait for the container to be ready
    info!("Waiting for container to be ready...");

    // Check if the port is accepting connections
    let mut retries = 10;
    let mut is_ready = false;
    while retries > 0 {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                info!("Container is ready on port {}", port);
                is_ready = true;
                break;
            }
            Err(_) => {
                warn!("Service not ready yet. Retrying...");
                sleep(Duration::from_millis(500)).await;
                retries -= 1;
            }
        }
    }

    if !is_ready {
        cleanup_container(&container_id);
        anyhow::bail!(
            "Service did not start properly (port {} is not accessible)",
            port
        );
    }

    info!("Service is ready. Executing request...");

    let client = reqwest::Client::new();
    let mut request = client.post(format!("http://127.0.0.1:{}", port));

    if let Some(input_path) = args.input_file {
        let content = fs::read(input_path)
            .await
            .context("Failed to read input file")?;
        request = request.body(content);
    }

    let response = request.send().await.context("Failed to make API request")?;

    // Get the response as bytes instead of text
    let response_bytes = response.bytes().await?;

    // Write the response to output.bin in the current directory
    let output_path = std::env::current_dir()?.join("output");
    fs::write(&output_path, response_bytes)
        .await
        .context("Failed to write response to output file")?;

    info!("Response saved to: {}", output_path.display());

    // Clean up and exit after saving response
    cleanup_container(&container_id);
    Ok(())
}
