![Marlin Oyster Logo](./logo.svg)

# Oyster CVM CLI

A command line utility to manage Oyster CVM lifecycle: build, upload, deploy and verify. Get started easily with just a `docker-compose` file.

## Prerequisites

- Docker (optional - required only for custom builds)
- Nix (optional - required only for custom builds)
- Git (for fetching flakes)

## Installation

### From source

#### Prerequisites

To build from source, ensure you have the following installed:
- **Rust**: The programming language required for building the project.
- **Cargo**: The Rust package manager and build system.

```bash
git clone https://github.com/marlinprotocol/oyster-monorepo.git
cd cli/oyster-cvm
cargo build --release
```

### Using nix

Supports both Linux and MacOS builds.

```
# linux amd64
nix build .#packages.x86_64-linux.default.cli.oyster-cvm.default

# linux arm64
nix build .#packages.aarch64-linux.default.cli.oyster-cvm.default

# macOS arm64 (Apple Silicon)
nix build .#packages.aarch64-darwin.default.cli.oyster-cvm.default
```

Note: macOS build can't be used to build custom oyster-cvm images.

## Usage

### View help

```bash
oyster-cvm --help
```

### Commands

#### `doctor`
Checks environment dependencies (optional). You can control which checks to run.

Optional args:
- `--check-docker`: Check if Docker is installed
- `--check-nix`: Check if Nix is installed

#### `build`
Builds an oyster-cvm image. Only needed for custom enclave images - you can use the base image for standard deployments.

Required args:
- `--platform` (amd64 or arm64)
- `--docker-compose` (path to docker-compose.yml)

Optional args:
- `--docker-images` (list of Docker .tar files to be loaded)
- `--output` (output directory, default: result)

#### `upload`
Uploads an enclave image to IPFS via Pinata.

Required args:
- `--file` (path to the enclave image file)

Required env vars:
["PINATA_API_KEY", "PINATA_API_SECRET"]

#### `verify`
Verifies an Oyster enclave's attestation document.

Required args:
- `--enclave-ip` (-e): Enclave IP address

Optional args:
- `--pcr0` (-0): PCR0 value
- `--pcr1` (-1): PCR1 value
- `--pcr2` (-2): PCR2 value
OR
- `--pcr-preset`: Use predefined PCR values for known images. Possible values: ["base/blue/v2.0.0/amd64", "base/blue/v2.0.0/arm64", "base/blue/v1.0.0/amd64", "base/blue/v1.0.0/arm64", "debug"]
OR
- `--pcr-json`: Pass the path to json file containing pcr values

- `--attestation-port` (-p): Attestation port (default: 1300)
- `--max-age` (-a): Maximum age of attestation in milliseconds (default: 300000)
- `--timestamp` (-t): Attestation timestamp in milliseconds (default: 0)
- `--root-public-key` (-r): Root public key (defaults to AWS root key)
- `--preset`: Preset for parameters (e.g. blue, debug)
- `--arch`: Platform architecture [default: arm64] [possible values: amd64, arm64]

#### `deploy`
Deploys an Oyster CVM instance.

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing
- `--duration-in-minutes`: Duration in minutes

Optional args:
- `--operator`: Operator address [default: 0xe10fa12f580e660ecd593ea4119cebc90509d642]
- `--preset`: Preset for parameters (e.g. blue) [default: blue]
- `--arch`: Platform architecture [default: arm64] [possible values: amd64, arm64]
- `--image-url`: URL of the enclave image (defaults to base image)
- `--region`: Region for deployment (defaults to ap-south-1)
- `--instance-type`: Instance type (defaults to r6g.large)
- `--bandwidth`: Bandwidth in KBps (default: 10)
- `--job-name`: Job name
- `--debug`: Start enclave in debug mode
- `--no-stream`: Disable automatic log streaming in debug mode (requires --debug)
- `--init-params-encoded`: Base64 encoded init params
- `--init-params`: List of init params in format `<path>:<attest>:<encrypt>:<type>:<value>`
- `--kms-endpoint`: Kms key gen endpoint (default: http://image-v3.kms.box:1101)
- `--kms-verification-key`: Kms response signature verification key
- `--docker-compose`: Path to custom docker-compose.yml file
- `--contract-address`: Enclave verifier contract address
- `--chain-id`: Chain ID for KMS contract root server
\
<br>
- `--pcr0` (-0): PCR0 value
- `--pcr1` (-1): PCR1 value
- `--pcr2` (-2): PCR2 value
<br>
OR
- `--pcr-preset`: Use predefined PCR values for known images. Possible values: ["base/blue/v2.0.0/amd64", "base/blue/v2.0.0/arm64", "base/blue/v1.0.0/amd64", "base/blue/v1.0.0/arm64", "debug"]
<br>
OR
- `--pcr-json`: Pass the path to json file containing pcr values

#### `update`
Updates an existing Oyster CVM job's metadata.

Required args:
- `--job-id`: ID of the job to update
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing

Optional args:
- `--image-url`: New image URL to update to
- `--debug`: Update debug mode setting

#### `logs`
Streams logs from an Oyster CVM instance.

Required args:
- `--ip` (-i): IP address of the instance

Optional args:
- `--start-from` (-s): Optional log ID to start streaming from
- `--with-log-id`(-w): Include log ID prefix in output (default: false)
- `--quiet` (-q): Suppress connection status message (default: false)

#### `list`
Lists all active jobs for a given wallet address.

Required args:
- `--wallet-address` (-w): The wallet address to list jobs for

Sample output:
```
+------------------+------------------+-------------+-----------+
| ID               | RATE (USDC/hour) | BALANCE     | PROVIDER |
+------------------+------------------+-------------+-----------+
| 0x123...         | 0.50            | 100.00 USDC | AWS      |
+------------------+------------------+-------------+-----------+
```

#### `deposit`
Deposits additional USDC funds to an existing job.

Required args:
- `--job-id` (-j): The ID of the job to deposit funds to
- `--amount` (-a): Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
- `--wallet-private-key`: Wallet private key for transaction signing

#### `stop`
Stops an Oyster CVM instance.

Required args:
- `--job-id` (-j): The ID of the job to stop
- `--wallet-private-key`: Wallet private key for transaction signing

#### `withdraw`
Withdraws USDC funds from an existing job. The command will first attempt to settle the job and then ensure a buffer balance is maintained for future operations.

Required args:
- `--job-id` (-j): The ID of the job to withdraw funds from
- `--wallet-private-key`: Wallet private key for transaction signing
- Either:
  - `--amount` (-a): Amount to withdraw in USDC (minimum 0.000001 USDC)
  - `--max`: Withdraw maximum available amount while maintaining required buffer

Note: A buffer balance of 7 minutes worth of job rate will be maintained to ensure smooth operation.

#### `compute-image-id`
Calculates the image ID based on the enclave image and input parameters. Intended to be used for applications using contract based KMS.

Optional args:
- `--preset`: Preset for parameters (e.g. blue, debug) [default: blue]
- `--arch`: Platform architecture [default: arm64] [possible values: amd64, arm64]
- `--init-params-encoded`: Base64 encoded init params
- `--init-params`: List of init params in format `<path>:<attest>:<encrypt>:<type>:<value>`
- `--docker-compose`: Path to custom docker-compose.yml file
- `--contract-address`: Enclave verifier contract address
- `--chain-id`: Chain ID for KMS contract root server
\
<br>
- `--pcr0` (-0): PCR0 value
- `--pcr1` (-1): PCR1 value
- `--pcr2` (-2): PCR2 value
<br>
OR
- `--pcr-preset`: Use predefined PCR values for known images. Possible values: ["base/blue/v2.0.0/amd64", "base/blue/v2.0.0/arm64", "base/blue/v1.0.0/amd64", "base/blue/v1.0.0/arm64", "debug"]
<br>
OR
- `--pcr-json`: Pass the path to json file containing pcr values

#### `kms-derive`
Fetches the KMS derived public keys or addresses  from root server.

Required args:
- `--path`: Derivation path of the key
- `--key-type`: Type of key to derive [possible values: secp256k1/public, secp256k1/address/ethereum, ed25519/public, ed25519/address/solana, x25519/public]

Optional args:
- `--kms-endpoint`: KMS endpoint for fetching public keys or addresses
- `--kms-verification-key`: Kms response signature verification key
\
<br>
- `--image-id`: Image ID of the enclave
<br>
OR
- `--contract-address`: Address of KMS verification contract
- `--chain-id`: Chain ID of KMS contract root server

#### `kms-contract deploy`
Deploys a KMS verify contract

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing

#### `kms-contract approve`
Approve the image ID on KMS verify contract

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing
- `--contract-address`: Address of KMS verification contract
- `--image-id`: Image ID of the enclave

#### `kms-contract revoke`
Revoke the image ID on KMS verify contract

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing
- `--contract-address`: Address of KMS verification contract
- `--image-id`: Image ID of the enclave

#### `kms-contract verify`
Verify the image ID on KMS verify contract

Required args:
- `--contract-address`: Address of KMS verification contract
- `--image-id`: Image ID of the enclave

### Example

```bash
# Check system requirements (optional)
./oyster-cvm doctor --check-docker --check-nix
# Sample output:
[INFO] Docker is installed ✓
[INFO] Nix is installed ✓

# Deploy using base image (quickstart)
./oyster-cvm deploy \
  --wallet-private-key-file ./key.txt \
  --operator "0x..." \
  --duration-in-minutes 60 \
  --job-name "my-oyster-job"

# Deploy with additional options
./oyster-cvm deploy \
  --image-url "ipfs://Qm..." \
  --wallet-private-key-file ./key.txt \
  --operator "0x..." \
  --instance-type "m5a.2xlarge" \
  --duration-in-minutes 60 \
  --bandwidth 200 \
  --job-name "my-custom-job" \
  --debug \
  --no-stream \
  --init-params-encoded "base64_encoded_string"\
  --docker-compose ./docker-compose.yml\
  --pcr-json ./result/pcrs.json

# Sample output:
[INFO] Starting deployment...
[INFO] Total cost: 0.15 USDC
[INFO] Total rate: 0.000045 ETH/hour
[INFO] Approving USDC spend...
[INFO] USDC approval transaction: 0x3cc...e70
[INFO] Job creation transaction: 0x38b...008
[INFO] Transaction successful! Waiting 3 minutes for job initialization...
[INFO] Transaction events processed...
[INFO] Job created with ID: 0x000...37a
[INFO] Waiting for enclave to start...
[INFO] Checking for IP address...
[INFO] Found IP address: 192.168.1.100
[INFO] TCP connection established successfully
[INFO] Attestation check successful
[INFO] Enclave is ready! IP address: 192.168.1.100

# Update an existing job
./oyster-cvm update \
  --job-id "0x000...37a" \
  --wallet-private-key-file ./key.txt \
  --image-url "ipfs://Qm..." \
  --debug true

# Build a custom image (optional)
./oyster-cvm build \
  --platform amd64 \
  --docker-compose ./docker-compose.yml \
  --output ./result
# Generates a folder "result" with files
# image.eif  log.txt  pcr.json

# Upload custom image to IPFS
./oyster-cvm upload --file ./result/image.eif
# Sample output:
[INFO] Successfully uploaded to Pinata: https://gateway.pinata.cloud/ipfs/Qm...

# Verify an enclave using PCR preset
./oyster-cvm verify \
  --enclave-ip 192.168.1.100 \
  --pcr-preset "base/blue/v2.0.0/amd64"

# Or verify with custom PCR values
./oyster-cvm verify \
  --enclave-ip 192.168.1.100 \
  --pcr0 pcr0_value \
  --pcr1 pcr1_value \
  --pcr2 pcr2_value

# Sample output:
[INFO] Connecting to attestation endpoint: http://192.168.1.100:1300/attestation/raw
[INFO] Successfully fetched attestation document
[INFO] Root public key: <hex-encoded-key>
[INFO] Enclave public key: <hex-encoded-key>
[INFO] Verification successful ✓

# Stream logs from an enclave
./oyster-cvm logs --ip 192.168.1.100

# Stream logs with additional options
./oyster-cvm logs \
  --ip 192.168.1.100 \
  --start-from abc123 \
  --with-log-id \
  --quiet

# Deposit additional funds to a job
./oyster-cvm deposit \
  --job-id "0x123..." \
  --amount 1000000 \
  --wallet-private-key "your-private-key"

# Sample output:
[INFO] Starting deposit...
[INFO] Depositing: 1.000000 USDC
[INFO] USDC approval transaction: 0x3cc...e70
[INFO] Deposit successful!
[INFO] Transaction hash: 0x38b...008

# Stop an oyster instance
./oyster-cvm stop \
  --job-id "0x000..." \
  --wallet-private-key "your-private-key"

# Sample output:
[INFO] Stopping oyster instance with:
[INFO]   Job ID: 0x000...
[INFO] Found job, initiating stop...
[INFO] Stop transaction sent: 0x03...1d
[INFO] Instance stopped successfully!
[INFO] Transaction hash: 0x03...1d

# Withdraw funds from a job (specific amount)
./oyster-cvm withdraw \
  --job-id "0x123..." \
  --amount 1000000 \
  --wallet-private-key "your-private-key"

# Sample output:
[INFO] Starting withdrawal process...
[INFO] Current balance: 5.000000 USDC, Required buffer: 1.500000 USDC
[INFO] Initiating withdrawal of 1.000000 USDC
[INFO] Withdrawal transaction sent. Transaction hash: 0x3cc...e70
[INFO] Withdrawal successful!

# Withdraw maximum available funds from a job
./oyster-cvm withdraw \
  --job-id "0x123..." \
  --max \
  --wallet-private-key "your-private-key"

# Sample output:
[INFO] Starting withdrawal process...
[INFO] Current balance: 5.000000 USDC, Required buffer: 1.500000 USDC
[INFO] Maximum withdrawal requested
[INFO] Initiating withdrawal of 3.500000 USDC
[INFO] Withdrawal transaction sent. Transaction hash: 0x38b...008
[INFO] Withdrawal successful!

# List active jobs for a wallet
./oyster-cvm list --wallet-address "0x123..."

# Sample output:
[INFO] Listing active jobs for wallet address: 0x123...
+------------------+------------------+-------------+-----------+
| ID               | RATE (USDC/hour) | BALANCE     | PROVIDER |
+------------------+------------------+-------------+-----------+
| 0x123...         | 0.50            | 100.00 USDC | AWS      |
+------------------+------------------+-------------+-----------+

# Calculate image ID
oyster-cvm compute-image-id --docker-compose docker-compose.yml --contract-address D0D6fF1C2FD450aBcB050896EeE16AE10A1aD3e1 --chain-id 42161 --pcr-preset debug

# Sample output
[INFO] oyster_cvm::args::init_params: digest path="docker-compose.yml" should_attest=true should_encrypt=false
[INFO] oyster_cvm::args::init_params: digest path="contract-address" should_attest=true should_encrypt=false
[INFO] oyster_cvm::args::init_params: digest path="root-server-config.json" should_attest=true should_encrypt=false
[INFO] oyster_cvm::args::init_params: Computed digest digest="27637e8805c4eabe6bd39ed0cc9ac9e66db731470e524b02ea99794298a093e2"
[INFO] oyster_cvm::commands::image_id: Image ID: aaa2e48fca87611a563556ad9d778f19c7c32a1a7c84242eeb57cbb1f7e33bf1

# Derive KMS keys using image ID
oyster-cvm kms-derive --image-id c7160a47e84b1cdd06095c78ce20fbc95967810357f4f590d560a5fa41f076ec --path signing-server --key-type ed25519/address/solana

# Sample output
[INFO] oyster_cvm::commands::derive: kms derived address address="7Nbd6bRg9cAGsRBYCpyUFWQyE9h57mksYg9P7iabgHD"

# Derive KMS keys using contract address
oyster-cvm  kms-derive --contract-address D0D6fF1C2FD450aBcB050896EeE16AE10A1aD3e1 --chain-id 42161 --path signing-server --key-type x25519/public

# Sample output
[INFO] oyster_cvm::commands::derive: kms derived key key="f81003ebf81644344f688d62d4e42c7d4247afe5cba0a1220c159467dd7f1d44"

# Deploy KMS verification contract
oyster-cvm kms-contract deploy --wallet-private-key-file ./key.txt

# Sample output
[INFO] oyster_cvm::commands::kms_contract: Contract deployed at: 0x206e0eEcac18a3Fb95a572f9c93F50eD34BB8795

# Approve image ID on KMS verification contract
oyster-cvm kms-contract approve --wallet-private-key-file ./key.txt --contract-address 0x206e0eEcac18a3Fb95a572f9c93F50eD34BB8795 --image-id b8e47c0bbee929d7e1d065e24aa6abefab3c509c2cf73d6d2ffe7e8093ca5796

# Sample output
[INFO] oyster_cvm::commands::kms_contract: Transaction hash: 0x75c7dd811e9b5316e042c40ceaa1dd8903ddfd4c5cf0638bb80b2fff611992cb

# Revoke image ID on KMS verification contract
oyster-cvm kms-contract revoke --wallet-private-key-file ./key.txt --contract-address 0x206e0eEcac18a3Fb95a572f9c93F50eD34BB8795 --image-id b8e47c0bbee929d7e1d065e24aa6abefab3c509c2cf73d6d2ffe7e8093ca5796

# Sample output
[INFO] oyster_cvm::commands::kms_contract: Transaction hash: 0x38f5087e0edd21c95b3f2b8f81234d92003c7c8724b1b2449fcc7558744a212b

# Verify image ID on KMS verification contract
oyster-cvm kms-contract verify --contract-address 0x206e0eEcac18a3Fb95a572f9c93F50eD34BB8795 --image-id b8e47c0bbee929d7e1d065e24aa6abefab3c509c2cf73d6d2ffe7e8093ca5796

# Sample output
[INFO] oyster_cvm::commands::kms_contract: Image ID is verified
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
