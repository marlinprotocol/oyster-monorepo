fn main() {
    println!("cargo:rerun-if-changed=migrations");
    println!(
        "cargo:warning=Database migrations changed. \
        Please ensure that src/schema.rs is updated accordingly!"
    );
}
