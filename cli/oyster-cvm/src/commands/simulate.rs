use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::signers::k256::sha2::{Digest, Sha256};
use alloy::sol;
use anyhow::{anyhow, Context, Result};
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use tracing::info;

use crate::configs::global::{ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS};
use crate::types::Platform;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

#[derive(Args, Default)]
pub struct SimulateArgs {
    /// Preset for parameters (e.g. blue)
    #[arg(long, default_value = "blue")]
    pub preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    pub arch: Platform,

    /// Path to docker-compose.yml file
    #[arg(short = 'c', long)]
    pub docker_compose: Option<String>,

    /// List of Docker image .tar file paths
    #[arg(short = 'd', long)]
    pub docker_images: Vec<String>,

    /// Init params list, supports the following forms:
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>`
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
    #[arg(short = 'i', long)]
    pub init_params: Vec<String>,

    /// Application ports to expose out of the local container
    #[arg(short = 'p', long)]
    pub expose_ports: Vec<String>,

    /// Operator address
    #[arg(long, default_value = "0xe10fa12f580e660ecd593ea4119cebc90509d642")]
    pub operator: String,

    /// Region for deployment
    #[arg(long, default_value = "ap-south-1")]
    pub region: String,

    /// Instance type (e.g. "r6g.large")
    #[arg(long)]
    pub instance_type: Option<String>,

    /// Local dev base image
    #[arg(short, long, default_value = "ayushkyadav/local-dev-image:latest")]
    pub base_image: String,

    /// Memory limit for the local dev container
    #[arg(long, conflicts_with = "instance_type")]
    pub container_memory: Option<String>,

    /// Job and Local dev container name
    #[arg(short, long, default_value = "oyster_local_dev_container")]
    pub job_name: String,

    /// Cleanup base dev image after testing
    #[arg(long)]
    pub cleanup: bool,

    /// Dry run the image locally
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize)]
struct Operator {
    allowed_regions: Vec<String>,
    min_rates: Vec<RateCard>,
}

#[derive(Serialize, Deserialize)]
struct RateCard {
    region: String,
    rate_cards: Vec<InstanceRate>,
}

#[derive(Serialize, Deserialize, Clone)]
struct InstanceRate {
    instance: String,
    min_rate: String,
    cpu: u32,
    memory: u32,
    arch: String,
}

#[derive(Debug, Deserialize)]
struct DockerStats {
    CPUPerc: String,
    MemUsage: String,
}

pub async fn simulate(args: SimulateArgs) -> Result<()> {
    info!("Simulating oyster local dev environment with:");
    info!("  Platform: {}", args.arch.as_str());

    let Some(docker_compose) = args.docker_compose else {
        return Err(anyhow!(
            "Docker-compose file must be provided for simulation!"
        ));
    };
    info!("  Docker compose: {}", docker_compose);

    let docker_images_list = args.docker_images.join(" ");
    if !docker_images_list.is_empty() {
        info!("  Docker images: {}", docker_images_list);
    }

    let init_params_list = args.init_params.join(" ");
    if !init_params_list.is_empty() {
        info!("  Init params: {}", init_params_list);
    }

    // Pull the base dev image
    let mut base_image = args.base_image;
    if !base_image.contains(':') {
        base_image.push_str(":latest");
    }
    info!(
        "Pulling dev base image {} to local docker daemon",
        base_image
    );
    let mut pull_image = Command::new("docker")
        .args(["pull", &base_image])
        .stdout(Stdio::inherit())
        .spawn()
        .context("Failed to pull docker image")?;
    let _ = pull_image.wait();

    // Define the ports to be exposed out of the container (default attestation ports added)
    let mut port_args = vec![
        "-p".to_string(),
        "1300:1300".to_string(),
        "-p".to_string(),
        "1301:1301".to_string(),
    ];
    for port in args.expose_ports {
        port_args.append(&mut vec!["-p".to_string(), format!("{}:{}", &port, &port)]);
    }

    let mut temp_dirs = Vec::new();
    // Define mount args for the container
    let mut mount_args: Vec<String> = Vec::new();

    // Mount the docker-compose file into the container
    let docker_compose_host_path =
        fs::canonicalize(&docker_compose).context("Invalid docker-compose path")?;
    mount_args.append(&mut vec![
        "-v".to_string(),
        format!(
            "{}:/app/docker-compose.yml",
            docker_compose_host_path.display()
        ),
    ]);

    // Load and mount the docker images required by the docker compose available in the local docker daemon to the container
    let docker_images_temp_dir = "docker-images-temp";
    let docker_compose_images = get_required_images(&docker_compose)?;

    if !args.dry_run && !docker_compose_images.is_empty() {
        let local_docker_images = Command::new("docker")
            .args(["images", "--format", "{{.Repository}}:{{.Tag}}"])
            .output()
            .context("Failed to fetch local docker images")?;
        let docker_images_stdout = String::from_utf8_lossy(&local_docker_images.stdout);

        let local_docker_compose_images = docker_images_stdout
            .lines()
            .map(String::from)
            .filter(|image| docker_compose_images.contains(image))
            .collect::<Vec<String>>();

        if !local_docker_compose_images.is_empty() {
            fs::create_dir_all(docker_images_temp_dir)
                .context("Failed to create docker-images-temp directory")?;
            temp_dirs.push(docker_images_temp_dir);

            let mut save_handles = vec![];

            for image in local_docker_compose_images {
                let image_tar_path = format!(
                    "{}/{}.tar",
                    docker_images_temp_dir,
                    image.replace("/", "_").replace(":", "_")
                );

                let handle = thread::spawn(move || {
                    info!("Saving {} to {}", image, image_tar_path);
                    let _ = Command::new("docker")
                        .args(["save", "-o", &image_tar_path, &image])
                        .status()
                        .map_err(|err| {
                            info!("Failed to save image {}: {}", &image, err);
                            err
                        });
                });

                save_handles.push(handle);
            }

            for handle in save_handles {
                let _ = handle.join();
            }

            let docker_images_host_path = fs::canonicalize(docker_images_temp_dir)
                .context("Invalid docker images temp directory path")?;
            mount_args.append(&mut vec![
                "-v".to_string(),
                format!("{}:/app/docker-images", docker_images_host_path.display(),),
            ]);
        }
    }

    // Mount the docker images provided by user onto the container
    for local_image in args.docker_images {
        let local_image_host_path =
            fs::canonicalize(local_image).context("Invalid local docker image path")?;
        mount_args.append(&mut vec![
            "-v".to_string(),
            format!(
                "{}:/app/docker-images/{}",
                local_image_host_path.display(),
                local_image_host_path.file_name().unwrap().to_str().unwrap()
            ),
        ]);
    }

    // Mount the init params into the container (create temporary files for the utf8 params)
    let init_params_utf_temp_dir = "init-params-utf-temp";
    fs::create_dir_all(init_params_utf_temp_dir)
        .context("Failed to create init-params-utf-temp directory")?;
    temp_dirs.push(init_params_utf_temp_dir);

    let digest = args
        .init_params
        .iter()
        .map(|param| {
            // extract components
            let param_components = param.splitn(5, ":").collect::<Vec<_>>();
            let should_attest = param_components[1] == "1";

            // everything should be normal components, no root or current or parent dirs
            if PathBuf::from(param_components[0])
                .components()
                .any(|x| !matches!(x, Component::Normal(_)))
            {
                return Err(anyhow!(
                    "Invalid init param enclave path: {}",
                    param_components[0]
                ));
            }

            let contents = match param_components[3] {
                "utf8" => {
                    let temp_file_path = format!(
                        "{}/{}",
                        init_params_utf_temp_dir,
                        param_components[0]
                            .rsplit_once('/')
                            .map_or(param_components[0], |(_, file_name)| file_name)
                    );
                    // Write the string to a temporary file
                    let mut file = File::create(&temp_file_path)
                        .context("Failed to create temp init param file")?;
                    writeln!(file, "{}", param_components[4])
                        .context("Failed to write to temp file")?;

                    let init_param_host_path =
                        fs::canonicalize(&temp_file_path).context("Invalid init param path")?;
                    mount_args.append(&mut vec![
                        "-v".to_string(),
                        format!(
                            "{}:/init-params/{}",
                            init_param_host_path.display(),
                            param_components[0]
                        ),
                    ]);
                    param_components[4].as_bytes().to_vec()
                }
                "file" => {
                    let init_param_host_path =
                        fs::canonicalize(param_components[4]).context("Invalid init param path")?;
                    mount_args.append(&mut vec![
                        "-v".to_string(),
                        format!(
                            "{}:/init-params/{}",
                            init_param_host_path.display(),
                            param_components[0]
                        ),
                    ]);
                    fs::read(param_components[4]).context("Failed to read init param file")?
                }
                _ => return Err(anyhow!("Unknown param type: {}", param_components[3])),
            };

            info!(path = param_components[0], should_attest, "digest");

            if !should_attest {
                return Ok(None);
            }

            let enclave_path = PathBuf::from("/init-params/".to_owned() + param_components[0]);
            // compute individual digest
            let mut hasher = Sha256::new();
            hasher.update(enclave_path.as_os_str().len().to_le_bytes());
            hasher.update(enclave_path.as_os_str().as_encoded_bytes());
            hasher.update(contents.len().to_le_bytes());
            hasher.update(contents);

            Ok(Some(hasher.finalize()))
        })
        .collect::<Result<Vec<_>>>()
        .context("Failed to compute individual digest")?
        .into_iter()
        .flatten()
        // accumulate further into a single hash
        .fold(Sha256::new(), |mut hasher, param_hash| {
            hasher.update(param_hash);
            hasher
        })
        .finalize();

    // Create and mount the init params digest into the container
    let digest_file_path = "init_param_digest";
    let mut file =
        File::create(&digest_file_path).context("Failed to create temp init param digest file")?;
    file.write_all(&digest)
        .context("Failed to write to temp file")?;

    let init_param_digest_host_path =
        fs::canonicalize(&digest_file_path).context("Invalid init param digest path")?;
    mount_args.append(&mut vec![
        "-v".to_string(),
        format!(
            "{}:/app/init-params-digest",
            init_param_digest_host_path.display()
        ),
    ]);

    // Define memory configuration for the container based on user input
    let mut config_args = vec![];
    if args.container_memory.is_some() {
        config_args.push(format!("--memory={}", args.container_memory.unwrap()));
    } else {
        match fetch_instance_memory(args.instance_type, args.arch, args.operator, args.region).await
        {
            Ok(memory) => config_args.push(format!("--memory={}MB", memory)),
            Err(err) => info!("Failed to fetch instance memory: {}", err),
        }
    }

    info!("Starting the dev container with user specified parameters");
    let mut run_container = Command::new("docker")
        .args(["run", "--privileged", "--rm", "-it"])
        .args(&port_args)
        .args(&mount_args)
        .args(&config_args)
        .args(["--name", &args.job_name])
        .arg(&base_image)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to start container")?;

    let monitor_stats_task = thread::spawn(move || monitor_container_stats(&args.job_name));

    let exit_status = run_container
        .wait()
        .context("Failed to wait on container")?;
    info!("Dev container exited with status: {}", exit_status);

    let _ = monitor_stats_task.join().unwrap();

    if args.cleanup {
        info!("Removing dev image...");
        let remove_status = Command::new("docker")
            .args(["rmi", &base_image])
            .status()
            .context("Failed to remove the pulled dev image")?;
        info!("Dev image removed with status: {}", remove_status);
    }

    // Clean up the temporary files and directories created for simulation
    for dir in temp_dirs {
        if let Err(err) = fs::remove_dir_all(dir) {
            info!("Failed to remove {} directory: {}", dir, err);
        }
    }

    if let Err(err) = fs::remove_file(digest_file_path) {
        info!("Failed to remove {} file: {}", digest_file_path, err);
    }

    Ok(())
}

// Parse the docker-compose file and fetch the images specified
fn get_required_images(docker_compose: &str) -> Result<HashSet<String>> {
    let docker_compose_content =
        fs::read_to_string(docker_compose).context("Failed to read docker-compose file")?;
    let yaml: Value =
        serde_yaml::from_str(&docker_compose_content).context("Invalid YAML format")?;

    Ok(yaml
        .get("services")
        .and_then(|services| services.as_mapping())
        .map(|services| {
            services
                .iter()
                .filter_map(|(_, service)| {
                    service
                        .get("image")
                        .and_then(|image| image.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default())
}

// Fetch memory corresponding to the instance type and platform
async fn fetch_instance_memory(
    instance_type: Option<String>,
    arch: Platform,
    operator: String,
    region: String,
) -> Result<u32> {
    let provider = ProviderBuilder::new().on_http(
        ARBITRUM_ONE_RPC_URL
            .parse()
            .context("Failed to parse RPC URL")?,
    );

    let market_address = Address::from_str(OYSTER_MARKET_ADDRESS)
        .context("Failed to parse oyster market address")?;
    let provider_address =
        Address::from_str(&operator).context("Failed to parse default operator address")?;
    let market = OysterMarket::new(market_address, provider);

    let cp_url = market
        .providers(provider_address)
        .call()
        .await
        .context("Failed to call oyster market providers")?
        .cp;
    let spec_url = format!("{}/spec", cp_url);

    let client = Client::new();
    let response = client
        .get(spec_url)
        .send()
        .await
        .context("Failed to call operator spec url")?;
    let operator: Operator = response.json().await?;

    let instance_type = instance_type.unwrap_or(match arch {
        Platform::AMD64 => "c6a.xlarge".into(),
        Platform::ARM64 => "c6g.large".into(),
    });

    for min_rate in operator.min_rates {
        if min_rate.region != region {
            continue;
        }

        for instance in min_rate.rate_cards {
            if instance.instance == instance_type {
                return Ok(instance.memory);
            }
        }
    }

    Err(anyhow!(
        "Failed to find a instance corresponding to the type: {}",
        instance_type
    ))
}

// Monitor container stats like memory and cpu usage
fn monitor_container_stats(container_name: &str) {
    thread::sleep(Duration::from_secs(2));
    info!("Monitoring task started...");

    let mut max_memory_usage = 0.0;
    let mut max_cpu_usage = 0.0;

    while is_container_running(container_name) {
        let Ok(mut cmd) = Command::new("docker")
            .args([
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                container_name,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                info!("Failed to fetch docker stats: {}", err);
                err
            })
        else {
            continue;
        };

        if let Some(stdout) = cmd.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else {
                    break;
                };

                if let Ok(stats) = serde_json::from_str::<DockerStats>(&line) {
                    let memory_usage = parse_memory(&stats.MemUsage);
                    let cpu_usage = parse_cpu(&stats.CPUPerc);

                    if memory_usage > max_memory_usage {
                        max_memory_usage = memory_usage;
                    }
                    if cpu_usage > max_cpu_usage {
                        max_cpu_usage = cpu_usage;
                    }
                }
            }
        }

        thread::sleep(Duration::from_secs(1));
    }

    info!("Max container CPU usage: {:.2}%", max_cpu_usage);
    info!("Max container Memory usage: {:.2} MiB", max_memory_usage);
}

// Check if the container is still running for monitoring purposes
fn is_container_running(container_name: &str) -> bool {
    let Ok(output) = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", container_name])
        .output()
        .map_err(|err| {
            info!("Failed to check container status: {}", err);
            err
        })
    else {
        return false;
    };

    let status = String::from_utf8_lossy(&output.stdout);
    status.trim() == "true"
}

fn parse_memory(mem_usage: &str) -> f64 {
    let parts: Vec<&str> = mem_usage.split('/').collect();
    if let Some(value) = parts.first() {
        let value = value.trim();
        if value.ends_with("GiB") {
            value[..value.len() - 3].parse::<f64>().unwrap_or(0.0) * 1024.0
        } else if value.ends_with("MiB") {
            value[..value.len() - 3].parse::<f64>().unwrap_or(0.0)
        } else if value.ends_with("KiB") {
            value[..value.len() - 3].parse::<f64>().unwrap_or(0.0) / 1024.0
        } else {
            0.0
        }
    } else {
        0.0
    }
}

fn parse_cpu(cpu_perc: &str) -> f64 {
    cpu_perc.trim_end_matches('%').parse::<f64>().unwrap_or(0.0)
}
