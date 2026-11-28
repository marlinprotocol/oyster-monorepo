use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// Path to the enclave log file
    #[clap(short, long)]
    pub enclave_log_file_path: String,

    /// Path to the script log file
    #[clap(short, long)]
    pub script_log_file_path: String,

    /// Target CID for the enclave (optional, default is 18)
    #[clap(short, long, default_value = "88")]
    pub target_cid: u64,

    #[clap(short, long, default_value = "516")]
    pub port: u16,

    /// Size in MB after which the enclave log file is rotated,
    /// one older file is kept next to it with a .1 suffix
    #[clap(long, default_value = "256")]
    pub max_log_file_size_mb: u64,
}
