use clap::Parser;
use methods::{GUEST_ELF, GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    println!(
        "GUEST: 0x{}",
        hex::encode(GUEST_ID.map(u32::to_le_bytes).as_flattened())
    );

    let args = Args::parse();

    // Query attestation from the given url
    let mut attestation = Vec::new();
    ureq::get(&args.url)
        .call()
        .unwrap()
        .into_reader()
        .read_to_end(&mut attestation)
        .unwrap();

    println!("Attestation size: {}", attestation.len());

    let env = ExecutorEnv::builder()
        .write_slice(&attestation)
        .build()
        .unwrap();

    let prover = default_prover();
    // Enable groth16
    let prove_info = prover
        .prove_with_opts(env, GUEST_ELF, &ProverOpts::groth16())
        .unwrap();

    let receipt = prove_info.receipt;

    println!("Receipt: {:?}", receipt);

    println!(
        "Seal: {}",
        hex::encode(&receipt.inner.groth16().unwrap().seal)
    );
    println!("Journal: {}", hex::encode(&receipt.journal.bytes));
}
