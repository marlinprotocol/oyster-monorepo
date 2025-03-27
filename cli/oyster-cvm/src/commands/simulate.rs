use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tracing::info;

#[derive(Args)]
pub struct SimulateArgs {
    /// Path to docker-compose.yml file
    #[arg(short = 'c', long)]
    docker_compose: String,

    /// List of Docker image .tar file paths
    #[arg(short = 'd', long)]
    docker_images: Vec<String>,

    /// Init params list, supports the following forms:
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>`
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
    #[arg(short = 'i', long)]
    init_params: Vec<String>,

    /// Local dev base image name
    #[arg(short, long, default_value = "ayushkyadav/local-dev-image")]
    image_name: String,

    /// Local dev base image tag
    #[arg(short, long, default_value = "latest")]
    image_tag: String,

    /// Memory limit for the local dev container
    #[arg(short, long)]
    memory: Option<String>,

    /// CPU shares to allocate to the local dev container
    #[arg(short, long)]
    cpu_shares: Option<u32>,

    /// Local dev container name
    #[arg(short, long, default_value = "oyster_local_dev_container")]
    container_name: String,
}

#[derive(Debug, Deserialize)]
struct DockerStats {
    CPUPerc: String,
    MemUsage: String,
}

pub async fn simulate(args: SimulateArgs) -> Result<()> {
    info!("Simulating oyster local dev environment with:");
    info!("  Docker compose: {}", args.docker_compose);

    let docker_images_list = args.docker_images.join(" ");
    if !docker_images_list.is_empty() {
        info!("  Docker images: {}", docker_images_list);
    }

    let init_params_list = args.init_params.join(" ");
    if !init_params_list.is_empty() {
        info!("  Init params: {}", init_params_list);
    }

    let full_image_name = format!("{}:{}", args.image_name, args.image_tag);
    info!(
        "Pulling dev base image {} to local docker daemon",
        full_image_name
    );
    let mut pull_image = Command::new("docker")
        .args(["pull", &full_image_name])
        .stdout(Stdio::inherit())
        .spawn()
        .context("Failed to pull docker image")?;
    let _ = pull_image.wait();

    let mut mount_args: Vec<String> = Vec::new();

    let docker_compose_host_path =
        fs::canonicalize(args.docker_compose).context("Invalid docker-compose path")?;
    mount_args.append(&mut vec![
        "-v".to_string(),
        format!(
            "{}:/app/docker-compose.yml",
            docker_compose_host_path.display()
        ),
    ]);

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

    let mut temp_file_paths = vec![];

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
                    let temp_file_path = format!("init_string_{}", temp_file_paths.len());
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
                            "{}:/app/init-params/{}",
                            init_param_host_path.display(),
                            param_components[0]
                        ),
                    ]);
                    temp_file_paths.push(temp_file_path);
                    param_components[4].as_bytes().to_vec()
                }
                "file" => {
                    let init_param_host_path =
                        fs::canonicalize(param_components[4]).context("Invalid init param path")?;
                    mount_args.append(&mut vec![
                        "-v".to_string(),
                        format!(
                            "{}:/app/init-params/{}",
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

    let digest_file_path = "init_param_digest";
    // Write the string to a temporary file
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
    temp_file_paths.push(digest_file_path.to_string());

    let mut config_args = vec![];
    if args.memory.is_some() {
        config_args.push(format!("--memory={}", args.memory.unwrap()));
    }

    if args.cpu_shares.is_some() {
        config_args.push(format!("--cpu-shares={}", args.cpu_shares.unwrap()));
    }

    info!("Starting the dev container with user specified parameters");
    let mut run_container = Command::new("docker")
        .args(["run", "--privileged", "--network=host", "--rm", "-it"])
        .args(&mount_args)
        .args(&config_args)
        .args(["--name", &args.container_name])
        .arg(&full_image_name)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to start container")?;

    let monitor_stats_task = thread::spawn(move || monitor_container_stats(&args.container_name));

    let exit_status = run_container
        .wait()
        .context("Failed to wait on container")?;
    info!("Dev container exited with status: {}", exit_status);

    let _ = monitor_stats_task.join().unwrap();

    info!("Removing dev image...");
    let remove_status = Command::new("docker")
        .args(["rmi", &full_image_name])
        .status()
        .context("Failed to remove the pulled dev image")?;
    info!("Dev image removed with status: {}", remove_status);

    for file_path in temp_file_paths.iter() {
        fs::remove_file(file_path).context("Failed to remove file")?;
    }

    Ok(())
}

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
