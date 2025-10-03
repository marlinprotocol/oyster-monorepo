use std::error::Error;
use std::path::PathBuf;

use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn Error>> {
    let proto_root = "proto";

    // Collect all .proto files under proto/
    let proto_files: Vec<PathBuf> = WalkDir::new(proto_root)
        .into_iter()
        .filter_map(|entry| {
            let path = entry.ok()?.into_path();
            if path.extension()? == "proto" {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    tonic_build::configure().build_client(true).compile(
        &proto_files
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect::<Vec<_>>(),
        &[proto_root],
    )?;

    Ok(())
}
