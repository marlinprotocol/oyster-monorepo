use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use aws_sdk_ec2::types::*;
use aws_types::region::Region;
use base64::{prelude::BASE64_STANDARD, Engine};
use coldsnap::{SnapshotUploader, SnapshotWaiter};
use rand_core::OsRng;
use ssh_key::sha2::{Digest, Sha256};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use ssh2::Session;
use tokio::time::{sleep, Duration};
use tokio_stream::StreamExt;
use tracing::{debug, error, info};
use whoami::username;

use crate::market::{InfraProvider, JobId};

#[derive(Clone)]
pub struct Aws {
    clients: HashMap<String, aws_sdk_ec2::Client>,
    ebs_clients: HashMap<String, aws_sdk_ebs::Client>,
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
        let mut ebs_clients = HashMap::<String, aws_sdk_ebs::Client>::new();
        for region in regions {
            clients.insert(region.clone(), {
                let config = aws_config::from_env()
                    .profile_name(&aws_profile)
                    .region(Region::new(region.clone()))
                    .load()
                    .await;
                aws_sdk_ec2::Client::new(&config)
            });
            ebs_clients.insert(region.clone(), {
                let config = aws_config::from_env()
                    .profile_name(&aws_profile)
                    .region(Region::new(region.clone()))
                    .load()
                    .await;
                aws_sdk_ebs::Client::new(&config)
            });
        }

        Aws {
            clients,
            ebs_clients,
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

    async fn ebs_client(&self, region: &str) -> &aws_sdk_ebs::Client {
        &self.ebs_clients[region]
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

    // [UPDATE NOTE] This function is obsolete, no enclaves
    // pub async fn run_enclave_impl(
    //     &self,
    //     job_id: &str,
    //     family: &str,
    //     instance_id: &str,
    //     region: &str,
    //     image_url: &str,
    //     req_vcpu: i32,
    //     req_mem: i64,
    //     bandwidth: u64,
    //     debug: bool,
    //     init_params: &[u8],
    // ) -> Result<()> {
    //     if family != "salmon" && family != "tuna" {
    //         return Err(anyhow!("unsupported image family"));
    //     }

    //     // make a ssh session
    //     let public_ip_address = self
    //         .get_instance_ip(instance_id, region)
    //         .await
    //         .context("could not fetch instance ip")?;
    //     let sess = &self
    //         .ssh_connect(&(public_ip_address + ":22"))
    //         .await
    //         .context("error establishing ssh connection")?;

    //     // set up ephemeral ports for the host
    //     Self::run_fragment_ephemeral_ports(sess)?;
    //     // set up nitro enclaves allocator
    //     Self::run_fragment_allocator(sess, req_vcpu, req_mem)?;
    //     // download enclave image and perform whitelist/blacklist checks
    //     self.run_fragment_download_and_check_image(sess, image_url)?;
    //     // set up bandwidth rate limiting
    //     Self::run_fragment_bandwidth(sess, bandwidth)?;

    //     if family == "tuna" {
    //         // set up iptables rules
    //         Self::run_fragment_iptables_tuna(sess)?;
    //         // set up job id in the init server
    //         Self::run_fragment_init_server(sess, job_id, init_params)?;
    //     } else {
    //         // set up iptables rules
    //         Self::run_fragment_iptables_salmon(sess)?;
    //     }

    //     // set up debug logger if enabled
    //     Self::run_fragment_logger(sess, debug)?;
    //     // run the enclave
    //     Self::run_fragment_enclave(sess, req_vcpu, req_mem, debug)?;

    //     Ok(())
    // }

    /* AWS EC2 UTILITY */
    // [UPDATE NOTE] Should return private IP, there won't be any Public IPs.
    pub async fn get_instance_public_ip(&self, instance_id: &str, region: &str) -> Result<String> {
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
        region: &str,
        init_params: &[u8],
        ami_id: &str,
    ) -> Result<String> {
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
        // [UPDATE NOTE] Add user data to launch instance
        Ok(self
            .client(region)
            .await
            .run_instances()
            .image_id(ami_id)
            .instance_type(instance_type)
            .min_count(1)
            .max_count(1)
            .tag_specifications(tags)
            .security_group_ids(sec_group)
            .subnet_id(subnet)
            .user_data(BASE64_STANDARD.encode(init_params))
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

    async fn get_job_snapshot_id(&self, job: &JobId, region: &str) -> Result<(bool, String)> {
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
            .describe_snapshots()
            .owner_ids("self")
            .filters(job_filter)
            .filters(operator_filter)
            .filters(contract_filter)
            .filters(chain_filter)
            .send()
            .await
            .context("could not describe instances")?;

        let own_snapshot = res.snapshots().iter().max_by_key(|x| &x.start_time);
        if let Some(snapshot) = own_snapshot {
            Ok((
                true,
                snapshot
                    .snapshot_id()
                    .ok_or(anyhow!("could not parse snapshot id"))?
                    .to_string(),
            ))
        } else {
            Ok((false, "".to_owned()))
        }
    }

    async fn get_job_ami_id(&self, job: &JobId, region: &str) -> Result<(bool, String)> {
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
            .describe_images()
            .owners("self")
            .filters(job_filter)
            .filters(operator_filter)
            .filters(contract_filter)
            .filters(chain_filter)
            .send()
            .await
            .context("could not describe instances")?;

        let own_ami = res.images().iter().max_by_key(|x| &x.name);
        if let Some(ami) = own_ami {
            Ok((
                true,
                ami.image_id()
                    .ok_or(anyhow!("could not parse image id"))?
                    .to_string(),
            ))
        } else {
            Ok((false, "".to_owned()))
        }
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

    // [UPDATE NOTE] Associate IP address to secondary IP of gateway VM
    async fn associate_address(
        &self,
        alloc_id: &str,
        region: &str,
        eni_id: &str,
        sec_id: &str,
    ) -> Result<()> {
        self.client(region)
            .await
            .associate_address()
            .allocation_id(alloc_id)
            .network_interface_id(eni_id)
            .private_ip_address(sec_id)
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

    // [UPDATE NOTE] Spin up instance is only kept, no run enclaves needed
    async fn spin_up_impl(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> Result<()> {
        let (mut exist, instance, state) = self
            .get_job_instance_id(job, region)
            .await
            .context("failed to get job instance")?;

        if exist {
            // instance exists already
            if state == "pending" || state == "running" {
                // instance exists and is already running, we are done
                info!(instance, "Found existing healthy instance");
            } else if state == "stopping" || state == "stopped" {
                // instance unhealthy, terminate
                info!(instance, "Found existing unhealthy instance");
                self.spin_down_instance(&instance, job, region)
                    .await
                    .context("failed to terminate instance")?;

                // set to false so new one can be provisioned
                exist = false;
            } else {
                // state is shutting-down or terminated
                // set to false so new one can be provisioned
                exist = false;
            }
        }

        // [UPDATE NOTE] Check AMI corresponding to given job. If dosen't exist then check if snapshot exists.
        // If doesn't exist download image upload as snapshot and register AMI. If snapshot exists register AMI from it.

        let (ami_exist, mut ami_id) = self
            .get_job_ami_id(job, region)
            .await
            .context("failed to get job ami")?;

        if !ami_exist {
            // check snapshot exists
            let (snapshot_exist, mut snapshot_id) = self
                .get_job_snapshot_id(job, region)
                .await
                .context("failed to get job snapshot")?;
            if !snapshot_exist {
                // 1. Download image in image_url to a tmp file
                // 2. check blacklist/whitelist
                // 3. Upload image as snapshot

                let tmp_file_path = format!("/tmp/image-{}.raw", job.id);
                let mut tmp_file = File::create(&tmp_file_path).context(format!(
                    "Failed to create temporary file for image {}",
                    tmp_file_path
                ))?;

                // Download the image from the image_url
                let resp = reqwest::get(image_url).await.context(format!(
                    "Failed to start download file from {} for job ID {}",
                    image_url, job.id
                ))?;
                let mut stream = resp.bytes_stream();

                while let Some(item) = stream.next().await {
                    let chunk = item.context(format!(
                        "Failed to read chunk from response stream for job ID {}",
                        job.id
                    ))?;
                    tmp_file.write_all(&chunk).context(format!(
                        "Failed to write chunk to temporary file for job ID {}",
                        job.id
                    ))?;
                }

                tmp_file.flush().context(format!(
                    "Failed to flush temporary file for job ID {}",
                    job.id
                ))?;

                let mut hasher = Sha256::new();
                let mut file = File::open(&tmp_file_path)
                    .context("Failed to open temporary file for hashing")?;
                let mut buffer = [0; 8192];
                loop {
                    let n = file
                        .read(&mut buffer)
                        .context("Failed to read temporary file")?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                let file_hash = hex::encode(hasher.finalize());

                if let Some(whitelist_list) = self.whitelist {
                    let mut allowed = false;
                    for entry in whitelist_list {
                        if entry.contains(&file_hash) {
                            allowed = true;
                            break;
                        }
                    }
                    if !allowed {
                        return Err(anyhow!("Image hash {} not found in whitelist", file_hash));
                    }
                }

                if let Some(blacklist_list) = self.blacklist {
                    for entry in blacklist_list {
                        if entry.contains(&file_hash) {
                            return Err(anyhow!("Image hash {} found in blacklist", file_hash));
                        }
                    }
                }

                let uploader = SnapshotUploader::new(self.ebs_client(region).await.clone());
                let managed_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("managedBy")
                    .value("marlin")
                    .build();
                let project_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("project")
                    .value("oyster")
                    .build();
                let job_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("jobId")
                    .value(&job.id)
                    .build();
                let operator_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("operator")
                    .value(&job.operator)
                    .build();
                let chain_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("chainID")
                    .value(&job.chain)
                    .build();
                let contract_tag = aws_sdk_ebs::types::Tag::builder()
                    .key("contractAddress")
                    .value(&job.contract)
                    .build();

                let snapshot_tags = vec![
                    managed_tag,
                    project_tag,
                    job_tag,
                    operator_tag,
                    contract_tag,
                    chain_tag,
                ];
                snapshot_id = uploader
                    .upload_from_file(
                        Path::new(&tmp_file_path),
                        None,
                        None,
                        Some(snapshot_tags),
                        None,
                        None,
                        None,
                    )
                    .await
                    .context("Failed to upload snapshot from image file")?;
                info!(snapshot_id, "Snapshot uploaded");
                let waiter = SnapshotWaiter::new(self.client(region).await.clone());
                waiter
                    .wait_for_completed(snapshot_id.as_str())
                    .await
                    .context("Failed to wait for snapshot completion")?;
                info!(snapshot_id, "Snapshot is now completed");
            }
            // Register AMI from snapshot

            let block_dev_mapping = BlockDeviceMapping::builder()
                .device_name("/dev/xvda")
                .ebs(
                    EbsBlockDevice::builder()
                        .snapshot_id(snapshot_id.clone())
                        .build(),
                )
                .build();

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
            let mut architecture = "arm64".to_string();
            let isntance_types = resp.instance_types();
            for instance in isntance_types {
                let supported_architectures = instance
                    .processor_info()
                    .ok_or(anyhow!("error fetching instance processor info"))?
                    .supported_architectures();
                if let Some(arch) = supported_architectures.iter().next() {
                    arch.as_str().clone_into(&mut architecture);
                    info!(architecture);
                }
            }
            let resp = self
                .client(region)
                .await
                .register_image()
                .name(format!("marlin/oyster/job-{}", job.id))
                .architecture(FromStr::from_str(&architecture)?)
                .root_device_name("/dev/xvda")
                .block_device_mappings(block_dev_mapping)
                .tpm_support(TpmSupportValues::V20)
                .virtualization_type("hvm".to_string())
                .boot_mode(BootModeValues::Uefi)
                .tag_specifications(
                    TagSpecification::builder()
                        .resource_type(ResourceType::Image)
                        .tags(Tag::builder().key("managedBy").value("marlin").build())
                        .tags(Tag::builder().key("project").value("oyster").build())
                        .tags(Tag::builder().key("jobId").value(&job.id).build())
                        .tags(Tag::builder().key("operator").value(&job.operator).build())
                        .tags(
                            Tag::builder()
                                .key("contractAddress")
                                .value(&job.contract)
                                .build(),
                        )
                        .tags(Tag::builder().key("chainID").value(&job.chain).build())
                        .build(),
                )
                .send()
                .await
                .context(format!(
                    "Failed to register AMI from snapshot {} for job {}",
                    snapshot_id, job.id
                ))?;

            ami_id = resp
                .image_id()
                .ok_or(anyhow!("could not parse image id"))?
                .to_string();
        }

        if !exist {
            // either no old instance or old instance was not enough, launch new one
            self.spin_up_instance(
                job,
                instance_type,
                region,
                req_mem,
                req_vcpu,
                init_params,
                ami_id.as_str(),
                bandwidth,
            )
            .await
            .context("failed to spin up instance")?;
        }

        Ok(())
        // [UPDATE NOTE] No enclave deployment needed. Check all the steps in this function if needed
        // Pick following:
        // 1. Rate limit configuration
        // 2. User Data setup
        // 3. Pick user image
        // self.run_enclave_impl(
        //     &job.id,
        //     family,
        //     &instance,
        //     region,
        //     image_url,
        //     req_vcpu,
        //     req_mem,
        //     bandwidth,
        //     debug,
        //     init_params,
        // )
        // .await
        // .context("failed to run enclave")
    }

    // [UPDATE NOTE] New things to add:
    // 1. Pick AMI corresponding to given image_url
    // 2. Setup user data
    pub async fn spin_up_instance(
        &self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        init_params: &[u8],
        ami_id: &str,
        bandwidth: u64,
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
        let mut v_cpus: i32 = 4;
        let mut mem: i64 = 8192;

        let instance_types = resp.instance_types();
        for instance in instance_types {
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
                .ok_or(anyhow!("error fetching instance memory info"))?;
            info!(mem);
        }

        if req_mem > mem || req_vcpu > v_cpus {
            return Err(anyhow!("Required memory or vcpus are more than available"));
        }
        let instance = self
            .launch_instance(job, instance_type, region, init_params, ami_id)
            .await
            .context("could not launch instance")?;
        sleep(Duration::from_secs(100)).await;

        let res = self.post_spin_up(job, &instance, region, bandwidth).await;

        if let Err(err) = res {
            error!(?err, "Error during post spin up");
            self.spin_down_instance(&instance, job, region)
                .await
                .context("could not spin down instance after error during post spin up")?;
            return Err(err).context("error during post spin up");
        }
        Ok(instance)
    }

    async fn post_spin_up(
        &self,
        job: &JobId,
        instance_id: &str,
        region: &str,
        bandwidth: u64,
    ) -> Result<()> {
        // [Update Note] do the networking here
        // Allocate Elastic IP
        // Check capacity on existing Rate Limit VM
        // Create secondary IP on Rate Limit VM
        // Modifictations on Rate Limit VM with NAT and tc
        // associate secondary IP and Elastic IP
        // Return
        let (alloc_id, ip) = self
            .allocate_ip_addr(job, region)
            .await
            .context("error allocating ip address")?;
        info!(ip, "Elastic Ip allocated");
        
        let (rl_instance_id, sec_ip, eni_id) = self
            .select_rate_limiter(region, bandwidth)
            .await
            .context("could not select rate limiter")?;
        info!(sec_ip, "Secondary IP allocated on Rate Limiter");

        self.configure_rate_limiter(
            &instance_id,
            &rl_instance_id,
            &sec_ip,
            &eni_id,
            bandwidth,
            region,
        )
        .await
        .context("could not configure rate limiter")?;


        self.associate_address(&alloc_id, region, &eni_id, &sec_ip)
            .await
            .context("could not associate ip address")?;
        Ok(())
    }

    async fn configure_rate_limiter(
        &self,
        instance_id: &str,
        rl_instance_id: &str,
        sec_ip: &str,
        eni_id: &str,
        bandwidth: u64,
        region: &str,
    ) -> Result<()> {
        // TODO: rollback on failure
        // SSH into Rate Limiter instance and configure NAT and tc
        let rl_ip = self
            .get_instance_public_ip(rl_instance_id, region)
            .await
            .context("could not get rate limiter instance ip")?;

        let sess = &self
            .ssh_connect(&(rl_ip + ":22"))
            .await
            .context("error establishing ssh connection")?;

        // Get instance private IP
        let private_ip = self
            .get_instance_private_ip(instance_id, region)
            .await
            .context("could not get instance private ip")?;

        // OPTION: Use a script file in rate limit VM, which take sec ip and private ip, bandwidth as args and setup
        // everything
        // setup NAT
        let nat_cmd = format!(
            "sudo nft add rule ip raw prerouting ip saddr {} notrack ip saddr set {} && \
sudo nft add rule ip raw prerouting ip daddr {} notrack ip daddr set {}",
            private_ip, sec_ip, sec_ip, private_ip
        );
        let (_, stderr) = Self::ssh_exec(sess, &nat_cmd).context("Failed to run nftable command")?;

        if !stderr.is_empty() {
            error!(stderr = ?stderr, "Error setting up NAT on Rate Limiter");
            // TODO: rollback on failure
            return Err(anyhow!(stderr)).context("Error setting up NAT on Rate Limiter");
        }

        // setup ip route table
        let ip_rule_cmd = format!(
            "sudo ip rule add from {} table {}",
            sec_ip, eni_id
        );
        // TODO: rollback on failure
        let (_, stderr) = Self::ssh_exec(sess, &ip_rule_cmd).context("Failed to run ip rule command")?;
        if !stderr.is_empty() {
            error!(stderr = ?stderr, "Error setting up IP rule on Rate Limiter");
            return Err(anyhow!(stderr)).context("Error setting up IP rule on Rate Limiter");
        }
        // setup tc
        // TODO: rollback on failure
        // TODO: get unique non-existent class_id
        // TODO: get device name from eni_id
        let class_id = 1;
        let tc_class_cmd = format!(
            "tc class add dev ens5 parent 1: classid 1:{} htb rate {} burst 15k",
            class_id,
            bandwidth
        );
        let tc_filter_cmd = format!(
            "tc filter add dev ens5 protocol ip parent 1:0 prio 1 u32 match ip src {} flowid 1:{}",
            sec_ip,
            class_id
        );

        let (_, stderr) = Self::ssh_exec(sess, &tc_class_cmd).context("Failed to run tc class command")?;
        if !stderr.is_empty() {
            error!(stderr = ?stderr, "Error setting up tc class on Rate Limiter");
            return Err(anyhow!(stderr)).context("Error setting up tc class on Rate Limiter");
        }
        let (_, stderr) = Self::ssh_exec(sess, &tc_filter_cmd).context("Failed to run tc filter command")?;
        if !stderr.is_empty() {
            error!(stderr = ?stderr, "Error setting up tc filter on Rate Limiter");
            return Err(anyhow!(stderr)).context("Error setting up tc filter on Rate Limiter");
        }


        Ok(())

    }

    async fn get_instance_private_ip(&self, instance_id: &str, region: &str) -> Result<String> {
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
            .private_ip_address()
            .ok_or(anyhow!("could not parse private ip address"))?
            .to_string())
    }

    async fn select_rate_limiter(&self, region: &str, bandwidth: u64) -> Result<(String, String, String)> {
        // get all the rate limiter vm from region
        // check available bandwidth and secondary IP is allowed
        // [Note] TODO manage concurrency resource issue
        // bandwidth is in kbit/sec
        let project_filter = Filter::builder()
            .name("tag:project")
            .values("oyster")
            .build();
        let rl_filter = Filter::builder()
            .name("tag:type")
            .values("rate-limiter")
            .build();
        let res = self
            .client(region)
            .await
            .describe_instances()
            .filters(project_filter)
            .filters(rl_filter)
            .send()
            .await
            .context("could not describe rate limit instances")?;

        let reservations = res.reservations();
        for reservation in reservations {
            for instance in reservation.instances() {
                let instance_id = instance
                    .instance_id()
                    .ok_or(anyhow!("could not parse instance id"))?
                    .to_string();
                // [TODO] atomically check & reserve available bandwidth (its kbit/sec, RL script takes in bits/sec)
                // attach a secondary IP to instance
                if instance.network_interfaces.is_none() {
                    debug!(
                        "No network interfaces found Rate Limit instance [{}]",
                        instance_id
                    );
                    continue;
                }
                for eni in instance.network_interfaces() {
                    if let Some(eni_id) = eni.network_interface_id() {
                        let res = self
                            .client(region)
                            .await
                            .assign_private_ip_addresses()
                            .network_interface_id(eni_id)
                            .secondary_private_ip_address_count(1)
                            .send()
                            .await;
                        if let Ok(assigned_ip) = res {
                            if assigned_ip.assigned_private_ip_addresses.is_none() {
                                debug!(
                                    "No secondary private IP address assigned Rate Limit instance [{}], ENI [{}]",
                                    instance_id,
                                    eni_id
                                );
                                continue;
                            } else {
                                let sec_ip = assigned_ip
                                    .assigned_private_ip_addresses()
                                    .first()
                                    .ok_or(anyhow!("no assigned private ip address found"))?
                                    .private_ip_address()
                                    .ok_or(anyhow!("no private ip address found"))?
                                    .to_string();
                                return Ok((instance_id, sec_ip, eni_id.to_string()));
                            }
                        } else {
                            debug!(
                                ?res,
                                "Error assigning secondary private IP address Rate Limit instance [{}], ENI [{}]",
                                instance_id,
                                eni_id
                            );
                            continue;
                        }
                    }
                }
                
            }
        }
        Err(anyhow!(
            "no rate limiter instance found with enough available bandwidth"
        ))
    }

    async fn spin_down_impl(&self, job: &JobId, region: &str) -> Result<()> {
        let (exist, instance, state) = self
            .get_job_instance_id(job, region)
            .await
            .context("failed to get job instance")?;

        if !exist || state == "shutting-down" || state == "terminated" {
            // instance does not really exist anyway, we are done
            info!("Instance does not exist or is already terminated");
            return Ok(());
        }

        // terminate instance
        info!(instance, "Terminating existing instance");
        self.spin_down_instance(&instance, job, region)
            .await
            .context("failed to terminate instance")?;

        Ok(())
    }
    // TODO: manage RL VM ops for remove VM
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
        self.terminate_instance(instance_id, region)
            .await
            .context("could not terminate instance")?;
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

        Ok(())
    }
}

impl InfraProvider for Aws {
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> Result<()> {
        self.spin_up_impl(
            job,
            instance_type,
            region,
            req_mem,
            req_vcpu,
            bandwidth,
            image_url,
            init_params,
        )
        .await
        .context("could not spin up enclave")
    }

    async fn spin_down(&mut self, job: &JobId, region: &str) -> Result<()> {
        self.spin_down_impl(job, region)
            .await
            .context("could not spin down enclave")
    }

    // [UPDATE NOTE] Due to Gateway VM rate limit, instance IP won't be equal to elastic IP. Instead, Gateway VM
    // secondary IPs are used.
    async fn get_job_ip(&self, job: &JobId, region: &str) -> Result<String> {
        let instance = self
            .get_job_instance_id(job, region)
            .await
            .context("could not get instance id for job instance ip")?;

        if !instance.0 {
            return Err(anyhow!("Instance not found for job - {}", job.id));
        }

        let (found, _, elastic_ip) = self
            .get_job_elastic_ip(job, region)
            .await
            .context("could not get job elastic ip")?;

        // It is possible that instance is still initializing and elastic IP is not yet associated
        if found {
            return Ok(elastic_ip);
        }

        Err(anyhow!("Instance is still initializing"))
    }

    async fn check_enclave_running(&mut self, job: &JobId, region: &str) -> Result<bool> {
        let (exists, instance_id, state) = self
            .get_job_instance_id(job, region)
            .await
            .context("could not get instance id for job")?;

        if !exists || (state != "running" && state != "pending") {
            return Ok(false);
        }
        // TODO: check wether state == pending is fine or not
        Ok(true)
    }
}

// write a test module for AWS struct spin up function
#[cfg(test)]
mod tests {
    use super::*;
    use crate::market::InfraProvider;
    use crate::market::JobId;

    #[tokio::test]
    async fn test_aws_spin_up_down() {
        let mut aws = Aws::new(
            "cp".to_string(),
            &["ap-southeast-2".to_string()],
            "cp".to_string(),
            None,
            None,
        )
        .await;
        let job = JobId {
            id: "test-job".to_string(),
            operator: "test-operator".to_string(),
            chain: "test-chain".to_string(),
            contract: "test-contract".to_string(),
        };
        let region = "ap-southeast-2";
        let instance_type = "t4g.micro";
        let req_mem = 1024;
        let req_vcpu = 2;
        let bandwidth = 100;
        let image_url = "https://example.com";
        let init_params = b"test-init-params";

        // Spin up
        let spin_up_result = aws
            .spin_up(
                &job,
                instance_type,
                region,
                req_mem,
                req_vcpu,
                bandwidth,
                image_url,
                init_params,
            )
            .await;
        assert!(
            spin_up_result.is_ok(),
            "Spin up failed: {:?}",
            spin_up_result.err()
        );

        // Check if running
        let is_running = aws
            .check_enclave_running(&job, region)
            .await
            .expect("Failed to check if enclave is running");
        assert!(is_running, "Enclave should be running after spin up");

        // Get job IP
        let job_ip_result = aws.get_job_ip(&job, region).await;
        assert!(
            job_ip_result.is_ok(),
            "Get job IP failed: {:?}",
            job_ip_result.err()
        );
        let job_ip = job_ip_result.unwrap();
        println!("Job IP: {}", job_ip);

        // Spin down
        let spin_down_result = aws.spin_down(&job, region).await;
        assert!(
            spin_down_result.is_ok(),
            "Spin down failed: {:?}",
            spin_down_result.err()
        );

        // Check if not running
        let is_running_after_down = aws
            .check_enclave_running(&job, region)
            .await
            .expect("Failed to check if enclave is running after spin down");
        assert!(
            !is_running_after_down,
            "Enclave should not be running after spin down"
        );
    }
}
