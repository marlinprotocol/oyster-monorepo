use std::error::Error;

use serverless::cgroups;

// Program to retrieve information about the 'cgroups' available inside the enclave currently
fn main() -> Result<(), Box<dyn Error>> {
    let cgroups = cgroups::Cgroups::new()?;
    println!("{:?}", cgroups.get_free_capacity());

    Ok(())
}
