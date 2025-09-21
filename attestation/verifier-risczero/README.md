![Marlin Oyster Logo](./logo.svg)

# Attestation Verifier - RiscZero

This project implements a RiscZero based AWS Nitro Enclave attestation verifier.

While it produces zero false positives, it does not aim to produce zero false negatives, i.e. it could reject _theoretically_ valid attestations. Instead, it asserts specific attestation formats that are _actually_ used in order to optimize proving time. It also does not verify any extensions in the certificates as it was deemed unnecessary.

## Build

Install the RiscZero tooling before proceeding further.

Note: Building requires CUDA by default. It is possible to disable CUDA by disabling default features using `--no-default-features`, but the proof generation process could take hours on a CPU. 

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds are NOT enabled by default for the guest. Set `RISC0_USE_DOCKER=1` while building as an env var to produce a consistent GUEST_ID.

```bash
RUSTFLAGS="-C target-cpu=native" RISC0_USE_DOCKER=1 cargo build --release
```

Expected GUEST_ID: 0x2bda5b8351181a4cfac4cab43439369ade055e546dd5af2026306985be64cad5

## Usage

```bash
$ ./target/release/host --help
GUEST: 0x2bda5b8351181a4cfac4cab43439369ade055e546dd5af2026306985be64cad5
Usage: host --url <URL>

Options:
  -u, --url <URL>  
  -h, --help       Print help
  -V, --version    Print version
```

It takes in a URL to an attestation server producing binary attestations.

## Journal format

The journal contains bytes in the following order:
- 8 byte timestamp in milliseconds from the attestation
- 32 byte image id computed by hashing the PCRs from the attestation
- 96 byte public key from the root certificate
- 1 byte length of the public key from the attestation
- N byte public key from the attestation
- 2 byte length of the user data from the attestation
- N byte user data from the attestation

## Directory Structure

```text
project_name
├── Cargo.toml
├── host
│   ├── Cargo.toml                     <-- [Feature to disable CUDA here]
│   └── src
│       └── main.rs                    <-- [Host code goes here]
└── methods
    ├── Cargo.toml
    ├── build.rs
    ├── guest
    │   ├── Cargo.toml
    │   └── src
    │       └── method_name.rs         <-- [Guest code goes here]
    └── src
        └── lib.rs
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
