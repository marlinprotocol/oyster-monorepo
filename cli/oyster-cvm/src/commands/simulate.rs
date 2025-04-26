use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::info;

use crate::types::Platform;

pub const LOCAL_DEV_IMAGE: &str = "marlinorg/local-dev-image:v1";

const LOCAL_DEV_DIRECTORY: &str = ".marlin";
const DOCKER_IMAGE_CACHE_DIRECTORY: &str = "local_dev_images";
const INIT_PARAMS_DIRECTORY: &str = "init_params";

/// Simulate oyster environment locally
#[derive(Args)]
pub struct SimulateArgs {
    /// Preset for parameters (e.g. blue)
    #[arg(long, default_value = "blue")]
    pub preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long)]
    pub arch: Option<Platform>,

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

    /// Local dev base image
    #[arg(short, long, default_value = LOCAL_DEV_IMAGE)]
    pub dev_image: String,

    /// Memory limit for the local dev container
    #[arg(long)]
    pub container_memory: Option<String>,

    /// Job and Local dev container name
    #[arg(short, long, default_value = "oyster_local_dev_container")]
    pub job_name: String,

    /// Cleanup local images cache after testing
    #[arg(long)]
    pub cleanup_cache: bool,

    /// Pull relevant local images or not
    #[arg(long)]
    pub no_local_images: bool,
}

#[derive(Debug, Deserialize)]
struct DockerStats {
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
}

#[derive(Debug, Deserialize)]
struct DockerInspectStats {
    #[serde(rename = "SizeRw")]
    size_rw: u64,
}

pub async fn simulate(args: SimulateArgs) -> Result<()> {
    info!("Simulating oyster local dev environment with:");
    let arch = match args.arch {
        Some(arch) => arch,
        None => get_system_arch()?,
    };

    info!("  Platform: {}", arch.as_str());

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

    info!(
        "Pulling dev base image {} to local docker daemon",
        args.dev_image
    );
    let mut pull_image = Command::new("docker")
        .args(["pull", &args.dev_image])
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

    // Define mount args for the container
    let mount_args: Arc<Mutex<Vec<String>>> = Mutex::new(Vec::new()).into();
    // Create directory for local dev files, if not present already
    if !PathBuf::from(LOCAL_DEV_DIRECTORY).exists() {
        fs::create_dir_all(LOCAL_DEV_DIRECTORY).context(format!(
            "Failed to create {} cache directory",
            LOCAL_DEV_DIRECTORY
        ))?;
    }

    // Mount the docker-compose file into the container
    let docker_compose_host_path =
        fs::canonicalize(&docker_compose).context("Invalid docker-compose path")?;
    mount_args.lock().unwrap().append(&mut vec![
        "-v".to_string(),
        format!(
            "{}:/app/docker-compose.yml",
            docker_compose_host_path.display()
        ),
    ]);

    if !args.no_local_images {
        // Load and mount the docker images required by the docker compose available in the local docker daemon to the container
        let docker_compose_images = get_required_images(&docker_compose)?;

        if !docker_compose_images.is_empty() {
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
                let local_images_cache =
                    format!("{}/{}", LOCAL_DEV_DIRECTORY, DOCKER_IMAGE_CACHE_DIRECTORY);
                if !PathBuf::from(&local_images_cache).exists() {
                    fs::create_dir_all(&local_images_cache).context(format!(
                        "Failed to create {} cache directory",
                        local_images_cache
                    ))?;
                }

                let mut save_handles = vec![];

                for image in local_docker_compose_images {
                    let mount_args_clone = mount_args.clone();
                    let local_images_cache = local_images_cache.clone();

                    let handle = thread::spawn(move || {
                        let Ok(image_id) = get_local_image_id(&image).map_err(|err| {
                            info!("{}", err);
                            err
                        }) else {
                            return;
                        };

                        if !is_present_in_cache(&image, &image_id, &local_images_cache) {
                            let _ = load_image_in_cache(&image, &image_id, &local_images_cache)
                                .map_err(|err| {
                                    info!("{}", err);
                                    err
                                });
                        }

                        let Ok(local_image_host_path) = fs::canonicalize(get_local_image_path(
                            &image,
                            &image_id,
                            &local_images_cache,
                        ))
                        .context("Invalid local docker image path")
                        .map_err(|err| {
                            info!("{}", err);
                            err
                        }) else {
                            return;
                        };
                        mount_args_clone.lock().unwrap().append(&mut vec![
                            "-v".to_string(),
                            format!(
                                "{}:/app/docker-images/{}",
                                local_image_host_path.display(),
                                local_image_host_path.file_name().unwrap().to_str().unwrap()
                            ),
                        ]);
                    });

                    save_handles.push(handle);
                }

                for handle in save_handles {
                    let _ = handle.join();
                }
            }
        }
    }

    // Mount the docker images provided by user onto the container
    for local_image in args.docker_images {
        let local_image_host_path =
            fs::canonicalize(local_image).context("Invalid local docker image path")?;
        mount_args.lock().unwrap().append(&mut vec![
            "-v".to_string(),
            format!(
                "{}:/app/docker-images/{}",
                local_image_host_path.display(),
                local_image_host_path.file_name().unwrap().to_str().unwrap()
            ),
        ]);
    }

    // Mount the init params into the container (create temporary files for the utf8 params)
    let init_params_path = format!("{}/{}", LOCAL_DEV_DIRECTORY, INIT_PARAMS_DIRECTORY);
    if !PathBuf::from(&init_params_path).exists() {
        fs::create_dir_all(&init_params_path).context(format!(
            "Failed to create {} cache directory",
            init_params_path
        ))?;
    }

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
                        init_params_path,
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
                    mount_args.lock().unwrap().append(&mut vec![
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
                    mount_args.lock().unwrap().append(&mut vec![
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
    let digest_file_path = format!("{}/init_param_digest", init_params_path);
    let mut file =
        File::create(&digest_file_path).context("Failed to create temp init param digest file")?;
    file.write_all(&digest)
        .context("Failed to write to temp file")?;

    let init_param_digest_host_path =
        fs::canonicalize(&digest_file_path).context("Invalid init param digest path")?;
    mount_args.lock().unwrap().append(&mut vec![
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
    }

    info!("Starting the dev container with user specified parameters");
    let mut run_container = Command::new("docker")
        .args([
            "run",
            "--privileged",
            "--rm",
            "-it",
            "--name",
            &args.job_name,
        ])
        .args(&port_args)
        .args(&*mount_args.lock().unwrap())
        .args(&config_args)
        .arg(&args.dev_image)
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

    // Clean up the temporary utf8 init params directory created for simulation
    if let Err(err) = fs::remove_dir_all(&init_params_path) {
        info!("Failed to remove {} directory: {}", init_params_path, err);
    }

    if args.cleanup_cache {
        if let Err(err) = fs::remove_dir_all(LOCAL_DEV_DIRECTORY) {
            info!(
                "Failed to remove {} directory: {}",
                LOCAL_DEV_DIRECTORY, err
            );
        }
    }

    Ok(())
}

fn get_system_arch() -> Result<Platform> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .context("Failed to run uname -m to get system architecture")?;

    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();

    match arch.as_str() {
        "x86_64" => Ok(Platform::AMD64),
        "aarch64" => Ok(Platform::ARM64),
        _ => Err(anyhow!("Unsupported architecture: {}", arch)),
    }
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
                        .map(|img| {
                            if img.contains(":") {
                                img
                            } else {
                                format!("{}:latest", img)
                            }
                        })
                })
                .collect()
        })
        .unwrap_or_default())
}

fn get_local_image_id(image_name: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(&["image", "inspect", image_name, "--format", "{{.Id}}"])
        .output()
        .context("Failed to call docker inspect")?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }

    Err(anyhow!(
        "Failed to fetch image ID for image: {} from local Daemon",
        image_name
    ))
}

fn get_local_image_path(image_name: &str, image_id: &str, cache_path: &str) -> String {
    format!(
        "{}/{}_{}.tar",
        cache_path,
        image_name.replace([':', '/'], "_"),
        image_id.split(':').nth(1).unwrap_or(image_id)
    )
}

fn is_present_in_cache(image_name: &str, image_id: &str, cache_path: &str) -> bool {
    let path = PathBuf::from(get_local_image_path(image_name, image_id, cache_path));
    return path.exists();
}

fn load_image_in_cache(image_name: &str, image_id: &str, cache_path: &str) -> Result<()> {
    if let Err(err) = remove_outdated_images(image_name, cache_path) {
        info!("Failed to remove outdated cache: {}", err);
    }

    info!("Saving image {} to local cache", image_name);
    let path = PathBuf::from(get_local_image_path(image_name, image_id, cache_path));
    let status = Command::new("docker")
        .args(["save", "-o"])
        .arg(&path)
        .arg(image_name)
        .status()
        .context("Failed to save image")?;

    if !status.success() {
        return Err(anyhow!("Failed status for saving the .tar file"));
    }

    info!(
        "Image {} saved to local cache at path: {}",
        image_name,
        path.display()
    );
    Ok(())
}

fn remove_outdated_images(image_name: &str, cache_path: &str) -> Result<()> {
    for entry in fs::read_dir(cache_path).context("Failed to read cache dir")? {
        let Ok(entry) = entry else {
            info!("Failed to read entry: {}", entry.unwrap_err());
            continue;
        };

        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                if file_name.starts_with(&image_name.replace([':', '/'], "_")) {
                    if let Err(err) = fs::remove_file(&path) {
                        info!("Failed to remove an outdated cached image: {}", err);
                        continue;
                    };

                    info!("Cache file deleted: {}", path.display());
                }
            }
        }
    }

    Ok(())
}

// Monitor container stats like memory and cpu usage
fn monitor_container_stats(container_name: &str) {
    info!("Monitoring task started...");

    let mut max_memory_usage = 0.0;
    let mut max_cpu_usage = 0.0;
    let mut max_disk_usage = 0.0;

    // Add some sleep for the container to be created
    thread::sleep(Duration::from_secs(2));

    while is_container_active(container_name) {
        let stats_output = Command::new("docker")
            .args([
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                container_name,
            ])
            .output();

        if let Ok(stats_output) = stats_output {
            if stats_output.status.success() {
                if let Ok(stats) = serde_json::from_slice::<DockerStats>(&stats_output.stdout) {
                    let memory_usage = parse_memory(&stats.mem_usage);
                    let cpu_usage = parse_cpu(&stats.cpu_perc);

                    if memory_usage > max_memory_usage {
                        max_memory_usage = memory_usage;
                    }
                    if cpu_usage > max_cpu_usage {
                        max_cpu_usage = cpu_usage;
                    }
                }
            }
        }

        let inspect_output = Command::new("docker")
            .args(["inspect", "--size", container_name])
            .output();

        if let Ok(inspect_output) = inspect_output {
            if inspect_output.status.success() {
                if let Ok(inspect_stats) =
                    serde_json::from_slice::<Vec<DockerInspectStats>>(&inspect_output.stdout)
                {
                    if let Some(stat) = inspect_stats.get(0) {
                        let size_usage = parse_size(stat.size_rw);

                        if size_usage > max_disk_usage {
                            max_disk_usage = size_usage;
                        }
                    }
                }
            }
        }

        thread::sleep(Duration::from_secs(1));
    }

    info!("Max container CPU usage: {:.2}%", max_cpu_usage);
    info!("Max container Memory usage: {:.2} MiB", max_memory_usage);
    info!("Max Disk usage: {:.2} MiB", max_disk_usage);
}

// Check if the container is active for monitoring purposes
fn is_container_active(container_name: &str) -> bool {
    let Ok(output) = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name={}", container_name),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .map_err(|err| {
            info!("Failed to check container status: {}", err);
            err
        })
    else {
        return false;
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.trim() == container_name;
    }

    false
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

fn parse_size(size_raw: u64) -> f64 {
    size_raw as f64 / 1024.0 / 1024.0
}
