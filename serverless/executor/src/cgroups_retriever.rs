use std::error::Error;

use serverless::cgroups;
use tracing::info;

// Program to retrieve information about the 'cgroups' available inside the enclave currently
fn main() -> Result<(), Box<dyn Error>> {
    let cgroups = cgroups::Cgroups::new()?;
    info!("{:?}", cgroups.free);

    Ok(())
}
