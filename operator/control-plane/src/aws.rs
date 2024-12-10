use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use aws_sdk_ec2::types::*;
use aws_types::region::Region;
use rand_core::OsRng;
use serde_json::Value;
use ssh2::Session;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use whoami::username;

use crate::market::{InfraProvider, JobId};

#[derive(Clone)]
pub struct Aws {
    clients: HashMap<String, aws_sdk_ec2::Client>,
    key_name: String,
    // Path cannot be cloned, hence String
    key_location: String,
    pub_key_location: String,
    whitelist: Option<&'static [String]>,
    blacklist: Option<&'static [String]>,
}

impl Aws {
    pub async fn new(
        aws_profile: String,
        regions: &[String],
        key_name: String,
        whitelist: Option<&'static [String]>,
        blacklist: Option<&'static [String]>,
    ) -> Aws {
        let key_location = "/home/".to_owned() + &username() + "/.ssh/" + &key_name + ".pem";
        let pub_key_location = "/home/".to_owned() + &username() + "/.ssh/" + &key_name + ".pub";

        let mut clients = HashMap::<String, aws_sdk_ec2::Client>::new();
        for region in regions {
            clients.insert(region.clone(), {
                let config = aws_config::from_env()
                    .profile_name(&aws_profile)
                    .region(Region::new(region.clone()))
                    .load()
                    .await;
                aws_sdk_ec2::Client::new(&config)
            });
        }

        Aws {
            clients,
            key_name,
            key_location,
            pub_key_location,
            whitelist,
            blacklist,
        }
    }

    async fn client(&self, region: &str) -> &aws_sdk_ec2::Client {
        &self.clients[region]
    }

    pub async fn generate_key_pair(&self) -> Result<()> {
        let priv_check = Path::new(&self.key_location).exists();
        let pub_check = Path::new(&self.pub_key_location).exists();

        if priv_check && pub_check {
            // both exist, we are done
            Ok(())
        } else if priv_check {
            // only private key exists, generate public key
            let private_key = PrivateKey::read_openssh_file(Path::new(&self.key_location))
                .context("Failed to read private key file")?;

            private_key
                .public_key()
                .write_openssh_file(Path::new(&self.pub_key_location))
                .context("Failed to write public key file")?;

            Ok(())
        } else if pub_check {
            // only public key exists, error out to avoid overwriting it
            Err(anyhow!("Found public key file without corresponding private key file, exiting to prevent overwriting it"))
        } else {
            // neither exist, generate private key and public key
            let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .context("Failed to generate private key")?;

            private_key
                .write_openssh_file(Path::new(&self.key_location), LineEnding::default())
                .context("Failed to write private key file")?;

            private_key
                .public_key()
                .write_openssh_file(Path::new(&self.pub_key_location))
                .context("Failed to write public key file")?;

            Ok(())
        }
    }

    pub async fn key_setup(&self, region: String) -> Result<()> {
        let key_check = self
            .check_key_pair(&region)
            .await
            .context("failed to check key pair")?;

        if !key_check {
            self.import_key_pair(&region)
                .await
                .with_context(|| format!("Failed to import key pair in {region}"))?;
        } else {
            info!(
                region,
                "Found existing keypair and pem file, skipping key setup"
            );
        }

        Ok(())
    }

    pub async fn import_key_pair(&self, region: &str) -> Result<()> {
        let f = File::open(&self.pub_key_location).context("Failed to open pub key file")?;
        let mut reader = BufReader::new(f);
        let mut buffer = Vec::new();

        reader
            .read_to_end(&mut buffer)
            .context("Failed to read pub key file")?;

        self.client(region)
            .await
            .import_key_pair()
            .key_name(&self.key_name)
            .public_key_material(aws_sdk_ec2::primitives::Blob::new(buffer))
            .send()
            .await
            .context("Failed to import key pair")?;

        Ok(())
    }

    async fn check_key_pair(&self, region: &str) -> Result<bool> {
        Ok(!self
            .client(region)
            .await
            .describe_key_pairs()
            .filters(
                Filter::builder()
                    .name("key-name")
                    .values(&self.key_name)
                    .build(),
            )
            .send()
            .await
            .context("failed to query key pairs")?
            .key_pairs()
            .is_empty())
    }

    /* SSH UTILITY */

    pub async fn ssh_connect(&self, ip_address: &str) -> Result<Session> {
        let tcp = TcpStream::connect(ip_address)?;

        let mut sess = Session::new()?;

        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        sess.userauth_pubkey_file("ubuntu", None, Path::new(&self.key_location), None)?;
        info!(ip_address, "SSH connection established");
        Ok(sess)
    }

    fn ssh_exec(sess: &Session, command: &str) -> Result<(String, String)> {
        let mut channel = sess
            .channel_session()
            .context("Failed to get channel session")?;
        let mut stdout = String::new();
        let mut stderr = String::new();
        channel
            .exec(command)
            .context("Failed to execute command: {command}")?;
        channel
            .read_to_string(&mut stdout)
            .context("Failed to read stdout")?;
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .context("Failed to read stderr")?;
        channel.wait_close().context("Failed to wait for close")?;

        Ok((stdout, stderr))
    }

    async fn check_eif_blacklist_whitelist(&self, sess: &Session) -> Result<bool> {
        if self.whitelist.is_some() || self.blacklist.is_some() {
            let (stdout, stderr) = Self::ssh_exec(sess, "sha256sum /home/ubuntu/enclave.eif")
                .context("Failed to calculate image hash")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Error calculating hash of enclave image: {stderr}"));
            }

            let line = stdout
                .split_whitespace()
                .next()
                .ok_or(anyhow!("Failed to retrieve image hash: {stdout}"))?;

            info!(line, "Hash");

            if let Some(whitelist_list) = self.whitelist {
                info!("Checking whitelist...");
                let mut allowed = false;
                for entry in whitelist_list {
                    if entry.contains(line) {
                        allowed = true;
                        break;
                    }
                }
                if allowed {
                    info!("EIF ALLOWED!");
                } else {
                    info!("EIF NOT ALLOWED!");
                    return Ok(false);
                }
            }

            if let Some(blacklist_list) = self.blacklist {
                info!("Checking blacklist...");
                let mut allowed = true;
                for entry in blacklist_list {
                    if entry.contains(line) {
                        allowed = false;
                        break;
                    }
                }
                if allowed {
                    info!("EIF ALLOWED!");
                } else {
                    info!("EIF NOT ALLOWED!");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub async fn run_enclave_impl(
        &self,
        job_id: &str,
        family: &str,
        instance_id: &str,
        region: &str,
        image_url: &str,
        req_vcpu: i32,
        req_mem: i64,
        bandwidth: u64,
        debug: bool,
    ) -> Result<()> {
        if family == "salmon" {
            self.run_enclave_salmon(
                job_id,
                instance_id,
                region,
                image_url,
                req_vcpu,
                req_mem,
                bandwidth,
                debug,
            )
            .await
        } else if family == "tuna" {
            self.run_enclave_tuna(
                job_id,
                instance_id,
                region,
                image_url,
                req_vcpu,
                req_mem,
                bandwidth,
                debug,
            )
            .await
        } else {
            Err(anyhow!("unsupported image family"))
        }
    }

    async fn run_enclave_salmon(
        &self,
        _job_id: &str,
        instance_id: &str,
        region: &str,
        image_url: &str,
        req_vcpu: i32,
        req_mem: i64,
        bandwidth: u64,
        debug: bool,
    ) -> Result<()> {
        let public_ip_address = self
            .get_instance_ip(instance_id, region)
            .await
            .context("could not fetch instance ip")?;
        let sess = &self
            .ssh_connect(&(public_ip_address + ":22"))
            .await
            .context("error establishing ssh connection")?;

        Self::ssh_exec(
            sess,
            &("echo -e '---\\nmemory_mib: ".to_owned()
                + &((req_mem).to_string())
                + "\\ncpu_count: "
                + &((req_vcpu).to_string())
                + "' | sudo tee /etc/nitro_enclaves/allocator.yaml"),
        )
        .context("Failed to set allocator file")?;

        let (_, stderr) = Self::ssh_exec(
            sess,
            "sudo systemctl restart nitro-enclaves-allocator.service",
        )
        .context("Failed to restart allocator service")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!(
                "Error restarting nitro-enclaves-allocator service: {stderr}"
            ));
        }

        info!(
            cpus = req_vcpu,
            memory = req_mem,
            "Nitro Enclave Service set up"
        );

        Self::ssh_exec(
            sess,
            &("curl -sL -o enclave.eif --max-filesize 4000000000 --max-time 120 ".to_owned()
                + image_url),
        )
        .context("Failed to download enclave image")?;

        let is_eif_allowed = self
            .check_eif_blacklist_whitelist(sess)
            .await
            .context("Failed to retrieve image hash")?;

        if !is_eif_allowed {
            return Err(anyhow!("EIF NOT ALLOWED"));
        }

        // store eif_url only when the image is allowed
        Self::ssh_exec(
            sess,
            &("echo \"".to_owned() + image_url + "\" > image_url.txt"),
        )
        .context("Failed to write EIF URL to txt file.")?;

        let (stdout, stderr) =
            Self::ssh_exec(sess, "nmcli device status").context("Failed to get nmcli status")?;
        if !stderr.is_empty() || stdout.is_empty() {
            error!(stderr);
            return Err(anyhow!("Error fetching network interface name: {stderr}"));
        }
        let mut interface = String::new();
        let entries: Vec<&str> = stdout.split('\n').collect();
        for line in entries {
            let entry: Vec<&str> = line.split_whitespace().collect();
            if entry.len() > 1 && entry[1] == "ethernet" {
                interface = entry[0].to_string();
                break;
            }
        }

        if !interface.is_empty() {
            let (stdout, stderr) = Self::ssh_exec(
                sess,
                &("sudo tc qdisc show dev ".to_owned() + &interface + " root"),
            )
            .context("Failed to fetch tc config")?;
            if !stderr.is_empty() || stdout.is_empty() {
                error!(stderr);
                return Err(anyhow!(
                    "Error fetching network interface qdisc configuration: {stderr}"
                ));
            }
            let entries: Vec<&str> = stdout.trim().split('\n').collect();
            let mut is_any_rule_set = true;
            if entries[0].to_lowercase().contains("qdisc mq 0: root") && entries.len() == 1 {
                is_any_rule_set = false;
            }

            // remove previously defined rules
            if is_any_rule_set {
                let (_, stderr) = Self::ssh_exec(
                    sess,
                    &("sudo tc qdisc del dev ".to_owned() + &interface + " root"),
                )?;
                if !stderr.is_empty() {
                    error!(stderr);
                    return Err(anyhow!(
                        "Error removing network interface qdisc configuration: {stderr}"
                    ));
                }
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                &("sudo tc qdisc add dev ".to_owned()
                    + &interface
                    + " root tbf rate "
                    + &bandwidth.to_string()
                    + "kbit burst 4000Mb latency 100ms"),
            )?;

            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Error setting up bandwidth limit: {stderr}"));
            }
        } else {
            return Err(anyhow!("Error fetching network interface name"));
        }

        let iptables_rules: [&str; 4] = [
            "-P PREROUTING ACCEPT",
            "-A PREROUTING -i ens5 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 1200",
            "-A PREROUTING -i ens5 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 1200",
            "-A PREROUTING -i ens5 -p tcp -m tcp --dport 1025:65535 -j REDIRECT --to-ports 1200",
        ];
        let (stdout, stderr) = Self::ssh_exec(sess, "sudo iptables -t nat -S PREROUTING")
            .context("Failed to query iptables")?;

        if !stderr.is_empty() || stdout.is_empty() {
            error!(stderr);
            return Err(anyhow!("Failed to get iptables rules: {stderr}"));
        }

        let rules: Vec<&str> = stdout.trim().split('\n').map(|s| s.trim()).collect();

        if rules[0] != iptables_rules[0] {
            error!(
                got = rules[0],
                expected = iptables_rules[0],
                "Rule mismatch"
            );
            return Err(anyhow!("Failed to get PREROUTING ACCEPT rules"));
        }

        if !rules.contains(&iptables_rules[1]) {
            let (_, stderr) = Self::ssh_exec(sess, "sudo iptables -A PREROUTING -t nat -p tcp --dport 80 -i ens5 -j REDIRECT --to-port 1200").context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        if !rules.contains(&iptables_rules[2]) {
            let (_, stderr) = Self::ssh_exec(sess, "sudo iptables -A PREROUTING -t nat -p tcp --dport 443 -i ens5 -j REDIRECT --to-port 1200").context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        if !rules.contains(&iptables_rules[3]) {
            let (_, stderr) = Self::ssh_exec(sess, "sudo iptables -A PREROUTING -t nat -p tcp --dport 1025:65535 -i ens5 -j REDIRECT --to-port 1200").context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        // set up logger if debug flag is set
        if debug {
            let (_, stderr) = Self::ssh_exec(sess, "curl -fsS https://artifacts.marlin.org/oyster/binaries/nitro-logger_v1.0.0_linux_`uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g'` -o nitro-logger && chmod +x nitro-logger")
                .context("Failed to download logger")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to download logger: {stderr}"));
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                "<<EOF cat | sudo tee /etc/supervisor/conf.d/logger.conf
[program:logger]
command=/home/ubuntu/nitro-logger --enclave-log-file-path /home/ubuntu/enclave.log --script-log-file-path /home/ubuntu/logger.log
autostart=true
autorestart=true
EOF
                ",
            )
            .context("Failed to setup supervisor conf")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to setup supervisor conf: {stderr}"));
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                "sudo supervisorctl reread && sudo supervisorctl update logger",
            )
            .context("Failed to start logger")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to start logger: {stderr}"));
            }
        }

        let (_, stderr) = Self::ssh_exec(
            sess,
            &("nitro-cli run-enclave --cpu-count ".to_owned()
                + &((req_vcpu).to_string())
                + " --memory "
                + &((req_mem).to_string())
                + " --eif-path enclave.eif --enclave-cid 88"
                + if debug { " --debug-mode" } else { "" }),
        )?;

        if !stderr.is_empty() {
            error!(stderr);
            if !stderr.contains("Started enclave with enclave-cid") {
                return Err(anyhow!("Error running enclave image: {stderr}"));
            }
        }

        info!("Enclave running");

        Ok(())
    }

    async fn run_enclave_tuna(
        &self,
        job_id: &str,
        instance_id: &str,
        region: &str,
        image_url: &str,
        req_vcpu: i32,
        req_mem: i64,
        bandwidth: u64,
        debug: bool,
    ) -> Result<()> {
        let public_ip_address = self
            .get_instance_ip(instance_id, region)
            .await
            .context("could not fetch instance ip")?;
        let sess = &self
            .ssh_connect(&(public_ip_address + ":22"))
            .await
            .context("error establishing ssh connection")?;

        let (_, stderr) = Self::ssh_exec(
            sess,
            "sudo sysctl -w net.ipv4.ip_local_port_range=\"61440 65535\"",
        )
        .context("Failed to set ephemeral ports")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!("Failed to set ephemeral ports: {stderr}"));
        }

        Self::ssh_exec(
            sess,
            &("echo -e '---\\nmemory_mib: ".to_owned()
                + &((req_mem).to_string())
                + "\\ncpu_count: "
                + &((req_vcpu).to_string())
                + "' | sudo tee /etc/nitro_enclaves/allocator.yaml"),
        )
        .context("Failed to set allocator file")?;

        let (_, stderr) = Self::ssh_exec(
            sess,
            "sudo systemctl restart nitro-enclaves-allocator.service",
        )
        .context("Failed to restart allocator service")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!(
                "Error restarting nitro-enclaves-allocator service: {stderr}"
            ));
        }

        info!(
            cpus = req_vcpu,
            memory = req_mem,
            "Nitro Enclave Service set up"
        );

        Self::ssh_exec(
            sess,
            &("curl -sL -o enclave.eif --max-filesize 4000000000 --max-time 120 ".to_owned()
                + image_url),
        )
        .context("Failed to download enclave image")?;

        let is_eif_allowed = self
            .check_eif_blacklist_whitelist(sess)
            .await
            .context("Failed to retrieve image hash")?;

        if !is_eif_allowed {
            return Err(anyhow!("EIF NOT ALLOWED"));
        }

        // store eif_url only when the image is allowed
        Self::ssh_exec(
            sess,
            &("echo \"".to_owned() + image_url + "\" > image_url.txt"),
        )
        .context("Failed to write EIF URL to txt file.")?;

        let (stdout, stderr) =
            Self::ssh_exec(sess, "nmcli device status").context("Failed to get nmcli status")?;
        if !stderr.is_empty() || stdout.is_empty() {
            error!(stderr);
            return Err(anyhow!("Error fetching network interface name: {stderr}"));
        }
        let mut interface = String::new();
        let entries: Vec<&str> = stdout.split('\n').collect();
        for line in entries {
            let entry: Vec<&str> = line.split_whitespace().collect();
            if entry.len() > 1 && entry[1] == "ethernet" {
                interface = entry[0].to_string();
                break;
            }
        }

        if !interface.is_empty() {
            let (stdout, stderr) = Self::ssh_exec(
                sess,
                &("sudo tc qdisc show dev ".to_owned() + &interface + " root"),
            )
            .context("Failed to fetch tc config")?;
            if !stderr.is_empty() || stdout.is_empty() {
                error!(stderr);
                return Err(anyhow!(
                    "Error fetching network interface qdisc configuration: {stderr}"
                ));
            }
            let entries: Vec<&str> = stdout.trim().split('\n').collect();
            let mut is_any_rule_set = true;
            if entries[0].to_lowercase().contains("qdisc mq 0: root") && entries.len() == 1 {
                is_any_rule_set = false;
            }

            // remove previously defined rules
            if is_any_rule_set {
                let (_, stderr) = Self::ssh_exec(
                    sess,
                    &("sudo tc qdisc del dev ".to_owned() + &interface + " root"),
                )?;
                if !stderr.is_empty() {
                    error!(stderr);
                    return Err(anyhow!(
                        "Error removing network interface qdisc configuration: {stderr}"
                    ));
                }
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                &("sudo tc qdisc add dev ".to_owned()
                    + &interface
                    + " root tbf rate "
                    + &bandwidth.to_string()
                    + "kbit burst 4000Mb latency 100ms"),
            )?;

            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Error setting up bandwidth limit: {stderr}"));
            }
        } else {
            return Err(anyhow!("Error fetching network interface name"));
        }

        let iptables_rules: [&str; 4] = [
            "-P INPUT ACCEPT",
            "-A INPUT -i ens5 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0",
            "-A INPUT -i ens5 -p tcp -m tcp --dport 443 -j NFQUEUE --queue-num 0",
            "-A INPUT -i ens5 -p tcp -m tcp --dport 1024:61439 -j NFQUEUE --queue-num 0",
        ];
        let (stdout, stderr) =
            Self::ssh_exec(sess, "sudo iptables -S INPUT").context("Failed to query iptables")?;

        if !stderr.is_empty() || stdout.is_empty() {
            error!(stderr);
            return Err(anyhow!("Failed to get iptables rules: {stderr}"));
        }

        let rules: Vec<&str> = stdout.trim().split('\n').map(|s| s.trim()).collect();

        if rules[0] != iptables_rules[0] {
            error!(
                got = rules[0],
                expected = iptables_rules[0],
                "Rule mismatch"
            );
            return Err(anyhow!("Failed to get PREROUTING ACCEPT rules"));
        }

        if !rules.contains(&iptables_rules[1]) {
            let (_, stderr) = Self::ssh_exec(
                sess,
                "sudo iptables -A INPUT -p tcp -i ens5 --dport 80 -j NFQUEUE --queue-num 0",
            )
            .context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        if !rules.contains(&iptables_rules[2]) {
            let (_, stderr) = Self::ssh_exec(
                sess,
                "sudo iptables -A INPUT -p tcp -i ens5 --dport 443 -j NFQUEUE --queue-num 0",
            )
            .context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        if !rules.contains(&iptables_rules[3]) {
            let (_, stderr) = Self::ssh_exec(
                sess,
                "sudo iptables -A INPUT -p tcp -i ens5 --dport 1024:61439 -j NFQUEUE --queue-num 0",
            )
            .context("Failed to set iptables rule")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to set iptables rule: {stderr}"));
            }
        }

        let (_, stderr) = Self::ssh_exec(
            sess,
            &("sudo sed -i -e 's/placeholder_job_id/".to_owned()
                + job_id
                + "/g' /etc/supervisor/conf.d/oyster-init-server.conf"),
        )
        .context("Failed to set job id for init server")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!("Failed to set job id for init server: {stderr}"));
        }

        let (_, stderr) = Self::ssh_exec(sess, "sudo supervisorctl update")
            .context("Failed to update init server")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!("Failed to update init server: {stderr}"));
        }

        // set up logger if debug flag is set
        if debug {
            let (_, stderr) = Self::ssh_exec(sess, "curl -fsS https://artifacts.marlin.org/oyster/binaries/nitro-logger_v1.0.0_linux_`uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g'` -o nitro-logger && chmod +x nitro-logger")
                .context("Failed to download logger")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to download logger: {stderr}"));
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                "<<EOF cat | sudo tee /etc/supervisor/conf.d/logger.conf
[program:logger]
command=/home/ubuntu/nitro-logger --enclave-log-file-path /home/ubuntu/enclave.log --script-log-file-path /home/ubuntu/logger.log
autostart=true
autorestart=true
EOF
                ",
            )
            .context("Failed to setup supervisor conf")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to setup supervisor conf: {stderr}"));
            }

            let (_, stderr) = Self::ssh_exec(
                sess,
                "sudo supervisorctl reread && sudo supervisorctl update logger",
            )
            .context("Failed to start logger")?;
            if !stderr.is_empty() {
                error!(stderr);
                return Err(anyhow!("Failed to start logger: {stderr}"));
            }
        }

        let (_, stderr) = Self::ssh_exec(
            sess,
            &("nitro-cli run-enclave --cpu-count ".to_owned()
                + &((req_vcpu).to_string())
                + " --memory "
                + &((req_mem).to_string())
                + " --eif-path enclave.eif --enclave-cid 88"
                + if debug { " --debug-mode" } else { "" }),
        )?;

        if !stderr.is_empty() {
            error!(stderr);
            if !stderr.contains("Started enclave with enclave-cid") {
                return Err(anyhow!("Error running enclave image: {stderr}"));
            }
        }

        info!("Enclave running");

        Ok(())
    }

    /* AWS EC2 UTILITY */

    pub async fn get_instance_ip(&self, instance_id: &str, region: &str) -> Result<String> {
        Ok(self
            .client(region)
            .await
            .describe_instances()
            .filters(
                Filter::builder()
                    .name("instance-id")
                    .values(instance_id)
                    .build(),
            )
            .send()
            .await
            .context("could not describe instances")?
            // response parsing from here
            .reservations()
            .first()
            .ok_or(anyhow!("no reservation found"))?
            .instances()
            .first()
            .ok_or(anyhow!("no instances with the given id"))?
            .public_ip_address()
            .ok_or(anyhow!("could not parse ip address"))?
            .to_string())
    }

    pub async fn launch_instance(
        &self,
        job: &JobId,
        instance_type: InstanceType,
        family: &str,
        architecture: &str,
        region: &str,
    ) -> Result<String> {
        let instance_ami = self
            .get_amis(region, family, architecture)
            .await
            .context("could not get amis")?;

        let enclave_options = EnclaveOptionsRequest::builder().enabled(true).build();
        let ebs = EbsBlockDevice::builder().volume_size(12).build();
        let block_device_mapping = BlockDeviceMapping::builder()
            .device_name("/dev/sda1")
            .ebs(ebs)
            .build();

        let name_tag = Tag::builder().key("Name").value("JobRunner").build();
        let managed_tag = Tag::builder().key("managedBy").value("marlin").build();
        let project_tag = Tag::builder().key("project").value("oyster").build();
        let job_tag = Tag::builder().key("jobId").value(&job.id).build();
        let operator_tag = Tag::builder().key("operator").value(&job.operator).build();
        let chain_tag = Tag::builder().key("chainID").value(&job.chain).build();
        let contract_tag = Tag::builder()
            .key("contractAddress")
            .value(&job.contract)
            .build();
        let tags = TagSpecification::builder()
            .resource_type(ResourceType::Instance)
            .tags(name_tag)
            .tags(managed_tag)
            .tags(project_tag)
            .tags(job_tag)
            .tags(operator_tag)
            .tags(contract_tag)
            .tags(chain_tag)
            .build();
        let subnet = self
            .get_subnet(region)
            .await
            .context("could not get subnet")?;
        let sec_group = self
            .get_security_group(region)
            .await
            .context("could not get subnet")?;

        Ok(self
            .client(region)
            .await
            .run_instances()
            .image_id(instance_ami)
            .instance_type(instance_type)
            .key_name(self.key_name.clone())
            .min_count(1)
            .max_count(1)
            .enclave_options(enclave_options)
            .block_device_mappings(block_device_mapping)
            .tag_specifications(tags)
            .security_group_ids(sec_group)
            .subnet_id(subnet)
            .send()
            .await
            .context("could not run instance")?
            // response parsing from here
            .instances()
            .first()
            .ok_or(anyhow!("no instance found"))?
            .instance_id()
            .ok_or(anyhow!("could not parse group id"))?
            .to_string())
    }

    async fn terminate_instance(&self, instance_id: &str, region: &str) -> Result<()> {
        let _ = self
            .client(region)
            .await
            .terminate_instances()
            .instance_ids(instance_id)
            .send()
            .await
            .context("could not terminate instance")?;

        Ok(())
    }

    pub async fn get_amis(&self, region: &str, family: &str, architecture: &str) -> Result<String> {
        let project_filter = Filter::builder()
            .name("tag:project")
            .values("oyster")
            .build();
        let name_filter = Filter::builder()
            .name("name")
            .values("marlin/oyster/worker-".to_owned() + family + "-" + architecture + "-????????")
            .build();

        let own_ami = self
            .client(region)
            .await
            .describe_images()
            .owners("self")
            .filters(project_filter)
            .filters(name_filter)
            .send()
            .await
            .context("could not describe images")?;

        let own_ami = own_ami.images().iter().max_by_key(|x| &x.name);

        if own_ami.is_some() {
            Ok(own_ami
                .unwrap()
                .image_id()
                .ok_or(anyhow!("could not parse image id"))?
                .to_string())
        } else {
            self.get_community_amis(region, family, architecture)
                .await
                .context("could not get community ami")
        }
    }

    pub async fn get_community_amis(
        &self,
        region: &str,
        family: &str,
        architecture: &str,
    ) -> Result<String> {
        let owner = "753722448458";
        let name_filter = Filter::builder()
            .name("name")
            .values("marlin/oyster/worker-".to_owned() + family + "-" + architecture + "-????????")
            .build();

        Ok(self
            .client(region)
            .await
            .describe_images()
            .owners(owner)
            .filters(name_filter)
            .send()
            .await
            .context("could not describe images")?
            // response parsing from here
            .images()
            .iter()
            .max_by_key(|x| &x.name)
            .ok_or(anyhow!("no images found"))?
            .image_id()
            .ok_or(anyhow!("could not parse image id"))?
            .to_string())
    }

    pub async fn get_security_group(&self, region: &str) -> Result<String> {
        let filter = Filter::builder()
            .name("tag:project")
            .values("oyster")
            .build();

        Ok(self
            .client(region)
            .await
            .describe_security_groups()
            .filters(filter)
            .send()
            .await
            .context("could not describe security groups")?
            // response parsing from here
            .security_groups()
            .first()
            .ok_or(anyhow!("no security group found"))?
            .group_id()
            .ok_or(anyhow!("could not parse group id"))?
            .to_string())
    }

    pub async fn get_subnet(&self, region: &str) -> Result<String> {
        let filter = Filter::builder()
            .name("tag:project")
            .values("oyster")
            .build();

        Ok(self
            .client(region)
            .await
            .describe_subnets()
            .filters(filter)
            .send()
            .await
            .context("could not describe subnets")?
            // response parsing from here
            .subnets()
            .first()
            .ok_or(anyhow!("no subnet found"))?
            .subnet_id()
            .ok_or(anyhow!("Could not parse subnet id"))?
            .to_string())
    }

    pub async fn get_job_instance_id(
        &self,
        job: &JobId,
        region: &str,
    ) -> Result<(bool, String, String)> {
        let job_filter = Filter::builder().name("tag:jobId").values(&job.id).build();
        let operator_filter = Filter::builder()
            .name("tag:operator")
            .values(&job.operator)
            .build();
        let chain_filter = Filter::builder()
            .name("tag:chainID")
            .values(&job.chain)
            .build();
        let contract_filter = Filter::builder()
            .name("tag:contractAddress")
            .values(&job.contract)
            .build();
        let res = self
            .client(region)
            .await
            .describe_instances()
            .filters(job_filter)
            .filters(operator_filter)
            .filters(contract_filter)
            .filters(chain_filter)
            .send()
            .await
            .context("could not describe instances")?;
        // response parsing from here
        let reservations = res.reservations();

        if reservations.is_empty() {
            Ok((false, "".to_owned(), "".to_owned()))
        } else {
            let instance = reservations[0]
                .instances()
                .first()
                .ok_or(anyhow!("instance not found"))?;
            Ok((
                true,
                instance
                    .instance_id()
                    .ok_or(anyhow!("could not parse ip address"))?
                    .to_string(),
                instance
                    .state()
                    .ok_or(anyhow!("could not parse instance state"))?
                    .name()
                    .ok_or(anyhow!("could not parse instance state name"))?
                    .as_str()
                    .to_owned(),
            ))
        }
    }

    pub async fn get_instance_state(&self, instance_id: &str, region: &str) -> Result<String> {
        Ok(self
            .client(region)
            .await
            .describe_instances()
            .filters(
                Filter::builder()
                    .name("instance-id")
                    .values(instance_id)
                    .build(),
            )
            .send()
            .await
            .context("could not describe instances")?
            // response parsing from here
            .reservations()
            .first()
            .ok_or(anyhow!("no reservation found"))?
            .instances()
            .first()
            .ok_or(anyhow!("no instances with the given id"))?
            .state()
            .ok_or(anyhow!("could not parse instance state"))?
            .name()
            .ok_or(anyhow!("could not parse instance state name"))?
            .as_str()
            .into())
    }

    pub async fn get_enclave_state(&self, instance_id: &str, region: &str) -> Result<String> {
        let public_ip_address = self
            .get_instance_ip(instance_id, region)
            .await
            .context("could not fetch instance ip")?;
        let sess = self
            .ssh_connect(&(public_ip_address + ":22"))
            .await
            .context("error establishing ssh connection")?;

        let (stdout, stderr) = Self::ssh_exec(&sess, "nitro-cli describe-enclaves")
            .context("could not describe enclaves")?;
        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!("Error describing enclaves: {stderr}"));
        }

        let enclave_data: Vec<HashMap<String, Value>> =
            serde_json::from_str(&stdout).context("could not parse enclave description")?;

        Ok(enclave_data
            .first()
            .and_then(|data| data.get("State").and_then(Value::as_str))
            .unwrap_or("No state found")
            .to_owned())
    }

    async fn allocate_ip_addr(&self, job: &JobId, region: &str) -> Result<(String, String)> {
        let (exist, alloc_id, public_ip) = self
            .get_job_elastic_ip(job, region)
            .await
            .context("could not get elastic ip for job")?;

        if exist {
            info!(public_ip, "Elastic Ip already exists");
            return Ok((alloc_id, public_ip));
        }

        let managed_tag = Tag::builder().key("managedBy").value("marlin").build();
        let project_tag = Tag::builder().key("project").value("oyster").build();
        let job_tag = Tag::builder().key("jobId").value(&job.id).build();
        let operator_tag = Tag::builder().key("operator").value(&job.operator).build();
        let chain_tag = Tag::builder().key("chainID").value(&job.chain).build();
        let contract_tag = Tag::builder()
            .key("contractAddress")
            .value(&job.contract)
            .build();
        let tags = TagSpecification::builder()
            .resource_type(ResourceType::ElasticIp)
            .tags(managed_tag)
            .tags(project_tag)
            .tags(job_tag)
            .tags(operator_tag)
            .tags(contract_tag)
            .tags(chain_tag)
            .build();

        let resp = self
            .client(region)
            .await
            .allocate_address()
            .domain(DomainType::Vpc)
            .tag_specifications(tags)
            .send()
            .await
            .context("could not allocate elastic ip")?;

        Ok((
            resp.allocation_id()
                .ok_or(anyhow!("could not parse allocation id"))?
                .to_string(),
            resp.public_ip()
                .ok_or(anyhow!("could not parse public ip"))?
                .to_string(),
        ))
    }

    async fn get_job_elastic_ip(
        &self,
        job: &JobId,
        region: &str,
    ) -> Result<(bool, String, String)> {
        let job_filter = Filter::builder().name("tag:jobId").values(&job.id).build();
        let operator_filter = Filter::builder()
            .name("tag:operator")
            .values(&job.operator)
            .build();
        let chain_filter = Filter::builder()
            .name("tag:chainID")
            .values(&job.chain)
            .build();
        let contract_filter = Filter::builder()
            .name("tag:contractAddress")
            .values(&job.contract)
            .build();

        Ok(
            match self
                .client(region)
                .await
                .describe_addresses()
                .filters(job_filter)
                .filters(operator_filter)
                .filters(contract_filter)
                .filters(chain_filter)
                .send()
                .await
                .context("could not describe elastic ips")?
                // response parsing starts here
                .addresses()
                .first()
            {
                None => (false, String::new(), String::new()),
                Some(addrs) => (
                    true,
                    addrs
                        .allocation_id()
                        .ok_or(anyhow!("could not parse allocation id"))?
                        .to_string(),
                    addrs
                        .public_ip()
                        .ok_or(anyhow!("could not parse public ip"))?
                        .to_string(),
                ),
            },
        )
    }

    async fn get_instance_elastic_ip(
        &self,
        instance: &str,
        region: &str,
    ) -> Result<(bool, String, String)> {
        let instance_id_filter = Filter::builder()
            .name("instance-id")
            .values(instance)
            .build();

        Ok(
            match self
                .client(region)
                .await
                .describe_addresses()
                .filters(instance_id_filter)
                .send()
                .await
                .context("could not describe elastic ips")?
                // response parsing starts here
                .addresses()
                .first()
            {
                None => (false, String::new(), String::new()),
                Some(addrs) => (
                    true,
                    addrs
                        .allocation_id()
                        .ok_or(anyhow!("could not parse allocation id"))?
                        .to_string(),
                    addrs
                        .association_id()
                        .ok_or(anyhow!("could not parse public ip"))?
                        .to_string(),
                ),
            },
        )
    }

    async fn associate_address(
        &self,
        instance_id: &str,
        alloc_id: &str,
        region: &str,
    ) -> Result<()> {
        self.client(region)
            .await
            .associate_address()
            .allocation_id(alloc_id)
            .instance_id(instance_id)
            .send()
            .await
            .context("could not associate elastic ip")?;
        Ok(())
    }

    async fn disassociate_address(&self, association_id: &str, region: &str) -> Result<()> {
        self.client(region)
            .await
            .disassociate_address()
            .association_id(association_id)
            .send()
            .await
            .context("could not disassociate elastic ip")?;
        Ok(())
    }

    async fn release_address(&self, alloc_id: &str, region: &str) -> Result<()> {
        self.client(region)
            .await
            .release_address()
            .allocation_id(alloc_id)
            .send()
            .await
            .context("could not release elastic ip")?;
        Ok(())
    }

    pub async fn spin_up_instance(
        &self,
        job: &JobId,
        instance_type: &str,
        family: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
    ) -> Result<String> {
        let instance_type =
            InstanceType::from_str(instance_type).context("cannot parse instance type")?;
        let resp = self
            .client(region)
            .await
            .describe_instance_types()
            .instance_types(instance_type.clone())
            .send()
            .await
            .context("could not describe instance types")?;
        let mut architecture = "amd64".to_string();
        let mut v_cpus: i32 = 4;
        let mut mem: i64 = 8192;

        let instance_types = resp.instance_types();
        for instance in instance_types {
            let supported_architectures = instance
                .processor_info()
                .ok_or(anyhow!("error fetching instance processor info"))?
                .supported_architectures();
            if let Some(arch) = supported_architectures.iter().next() {
                if arch.as_str() == "x86_64" {
                    "amd64".clone_into(&mut architecture);
                } else {
                    "arm64".clone_into(&mut architecture);
                }
                info!(architecture);
            }
            v_cpus = instance
                .v_cpu_info()
                .ok_or(anyhow!("error fetching instance v_cpu info"))?
                .default_v_cpus()
                .ok_or(anyhow!("error fetching instance v_cpu info"))?;
            info!(v_cpus);
            mem = instance
                .memory_info()
                .ok_or(anyhow!("error fetching instance memory info"))?
                .size_in_mib()
                .ok_or(anyhow!("error fetching instance v_cpu info"))?;
            info!(mem);
        }

        if req_mem > mem || req_vcpu > v_cpus {
            return Err(anyhow!("Required memory or vcpus are more than available"));
        }
        let instance = self
            .launch_instance(job, instance_type, family, &architecture, region)
            .await
            .context("could not launch instance")?;
        sleep(Duration::from_secs(100)).await;

        let res = self.post_spin_up(job, &instance, region).await;

        if let Err(err) = res {
            error!(?err, "Error during post spin up");
            self.spin_down_instance(&instance, job, region)
                .await
                .context("could not spin down instance after error during post spin up")?;
            return Err(err).context("error during post spin up");
        }
        Ok(instance)
    }

    async fn post_spin_up(&self, job: &JobId, instance: &str, region: &str) -> Result<()> {
        let (alloc_id, ip) = self
            .allocate_ip_addr(job, region)
            .await
            .context("error allocating ip address")?;
        info!(ip, "Elastic Ip allocated");

        self.associate_address(instance, &alloc_id, region)
            .await
            .context("could not associate ip address")?;
        Ok(())
    }

    pub async fn spin_down_instance(
        &self,
        instance_id: &str,
        job: &JobId,
        region: &str,
    ) -> Result<()> {
        let (exist, _, association_id) = self
            .get_instance_elastic_ip(instance_id, region)
            .await
            .context("could not get elastic ip of instance")?;
        if exist {
            self.disassociate_address(association_id.as_str(), region)
                .await
                .context("could not disassociate address")?;
        }
        let (exist, alloc_id, _) = self
            .get_job_elastic_ip(job, region)
            .await
            .context("could not get elastic ip of job")?;
        if exist {
            self.release_address(alloc_id.as_str(), region)
                .await
                .context("could not release address")?;
            info!("Elastic IP released");
        }

        self.terminate_instance(instance_id, region)
            .await
            .context("could not terminate instance")?;
        Ok(())
    }

    pub async fn update_enclave_image_impl(
        &self,
        instance_id: &str,
        region: &str,
        eif_url: &str,
        req_vcpu: i32,
        req_mem: i64,
    ) -> Result<()> {
        let public_ip_address = self
            .get_instance_ip(instance_id, region)
            .await
            .context("could not fetch instance ip")?;

        let sess = &self
            .ssh_connect(&(public_ip_address + ":22"))
            .await
            .context("error establishing ssh connection")?;

        let (stdout, stderr) =
            Self::ssh_exec(sess, "cat image_url.txt").context("Failed to read image_url.txt")?;

        if stderr.is_empty() && stdout == eif_url {
            return Ok(());
        }

        Self::ssh_exec(
            sess,
            &("curl -sL -o enclave.eif --max-filesize 4000000000 --max-time 120 ".to_owned()
                + eif_url),
        )
        .context("Failed to download enclave image")?;

        let is_eif_allowed = self
            .check_eif_blacklist_whitelist(sess)
            .await
            .context("Failed to retrieve image hash")?;

        if !is_eif_allowed {
            return Err(anyhow!("EIF NOT ALLOWED"));
        }

        Self::ssh_exec(
            sess,
            &("echo \"".to_owned() + eif_url + "\" > image_url.txt"),
        )
        .context("Failed to write EIF URL to txt file.")?;

        let (_, stderr) = Self::ssh_exec(sess, "nitro-cli terminate-enclave --all")?;

        if !stderr.is_empty() {
            error!(stderr);
            return Err(anyhow!("Error terminating enclave: {stderr}"));
        }

        let (_, stderr) = Self::ssh_exec(
            sess,
            &("nitro-cli run-enclave --cpu-count ".to_owned()
                + &((req_vcpu).to_string())
                + " --memory "
                + &((req_mem).to_string())
                + " --eif-path enclave.eif --enclave-cid 88"),
        )?;

        if !stderr.is_empty() {
            error!(stderr);
            if !stderr.contains("Started enclave with enclave-cid") {
                return Err(anyhow!("Error running enclave image: {stderr}"));
            }
        }

        info!("Enclave running");

        Ok(())
    }
}

impl InfraProvider for Aws {
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        family: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        _bandwidth: u64,
    ) -> Result<String> {
        let instance = self
            .spin_up_instance(job, instance_type, family, region, req_mem, req_vcpu)
            .await
            .context("could not spin up instance")?;
        Ok(instance)
    }

    async fn spin_down(&mut self, instance_id: &str, job: &JobId, region: &str) -> Result<()> {
        self.spin_down_instance(instance_id, job, region)
            .await
            .context("could not spin down instance")
    }

    async fn get_job_instance(&self, job: &JobId, region: &str) -> Result<(bool, String, String)> {
        self.get_job_instance_id(job, region)
            .await
            .context("could not get instance id for job")
    }

    async fn get_job_ip(&self, job: &JobId, region: &str) -> Result<String> {
        let instance = self
            .get_job_instance(job, region)
            .await
            .context("could not get instance id for job instance ip")?;

        if !instance.0 {
            return Err(anyhow!("Instance not found for job - {}", job.id));
        }

        let instance_ip = self
            .get_instance_ip(&instance.1, region)
            .await
            .context("could not get instance ip")?;

        let (found, _, elastic_ip) = self
            .get_job_elastic_ip(job, region)
            .await
            .context("could not get job elastic ip")?;

        // it is possible for the two above to differ while the instance is initializing (maybe
        // terminating?), better to error out instead of potentially showing a temporary IP
        if found && instance_ip == elastic_ip {
            return Ok(instance_ip);
        }

        Err(anyhow!("Instance is still initializing"))
    }

    async fn check_instance_running(&mut self, instance_id: &str, region: &str) -> Result<bool> {
        let res = self
            .get_instance_state(instance_id, region)
            .await
            .context("could not get current instance state")?;
        Ok(res == "running" || res == "pending")
    }

    async fn check_enclave_running(&mut self, instance_id: &str, region: &str) -> Result<bool> {
        let res = self
            .get_enclave_state(instance_id, region)
            .await
            .context("could not get current enclace state")?;
        // There can be 2 states - RUNNING or TERMINATING
        Ok(res == "RUNNING")
    }

    async fn run_enclave(
        &mut self,
        job: &JobId,
        instance_id: &str,
        family: &str,
        region: &str,
        image_url: &str,
        req_vcpu: i32,
        req_mem: i64,
        bandwidth: u64,
        debug: bool,
    ) -> Result<()> {
        self.run_enclave_impl(
            &job.id,
            family,
            instance_id,
            region,
            image_url,
            req_vcpu,
            req_mem,
            bandwidth,
            debug,
        )
        .await
        .context("could not run enclave")?;
        Ok(())
    }

    async fn update_enclave_image(
        &mut self,
        instance_id: &str,
        region: &str,
        eif_url: &str,
        req_vcpu: i32,
        req_mem: i64,
    ) -> Result<()> {
        self.update_enclave_image_impl(instance_id, region, eif_url, req_vcpu, req_mem)
            .await
            .context("could not update enclave image")?;
        Ok(())
    }
}
