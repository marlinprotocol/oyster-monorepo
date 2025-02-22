use clap::Args;

use super::pcr::PcrArgs;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct InitParamsArgs {
    /// Base64 encoded init params
    #[arg(short = 'e', long, exclusive = true)]
    pub init_params_encoded: Option<String>,

    /// Init params list, supports the following forms:
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>`
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
    #[arg(short = 'i', long)]
    pub init_params: Option<Vec<String>>,

    /// KMS endpoint for fetching public key for encryption
    #[arg(short = 'k', long)]
    pub kms_endpoint: Option<String>,

    /// Expected PCRs of the decryptor
    #[command(flatten)]
    pub pcrs: PcrArgs,
}
