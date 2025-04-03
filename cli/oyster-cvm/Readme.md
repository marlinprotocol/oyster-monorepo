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

#### `simulate`
Simulates the oyster-cvm environment locally inside a docker container.

Required args:
- `--arch` (platform architecture (e.g. amd64, arm64))
- `--docker-compose` (path to docker-compose.yml file)

Optional args:
- `--docker-images` (list of Docker image .tar file paths)
- `--init-params` (list of init params in format `<path>:<attest>:<encrypt>:<type>:<value>`)
- `--expose-ports` (application ports to expose out of the local container)
- `--instance-type` (instance type (e.g. "r6g.large"))
- `--image-name` (local dev base image name)
- `--image-tag` (local dev base image tag)
- `--container-memory` (memory limit for the local dev container)
- `--container-name` (local dev container name)
- `--cleanup` (cleanup base dev image after testing)

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
- `--pcr-preset`: Use predefined PCR values for known images. Possible values: ["base/blue/v1.0.0/amd64", "base/blue/v1.0.0/arm64"]
OR
- `--pcr-json`: Pass the path to json file containing pcr values

- `--attestation-port` (-p): Attestation port (default: 1300)
- `--max-age` (-a): Maximum age of attestation in milliseconds (default: 300000)
- `--timestamp` (-t): Attestation timestamp in milliseconds (default: 0)
- `--root-public-key` (-r): Root public key (defaults to AWS root key)

#### `deploy`
Deploys an Oyster CVM instance.

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing
- `--operator`: Operator address
- `--duration-in-minutes`: Duration in minutes

Optional args:
- `--image-url`: URL of the enclave image (defaults to base image)
- `--region`: Region for deployment (defaults to ap-south-1)
- `--instance-type`: Instance type (defaults to r6g.large)
- `--bandwidth`: Bandwidth in KBps (default: 10)
- `--job-name`: Job name
- `--debug`: Start enclave in debug mode
- `--no-stream`: Disable automatic log streaming in debug mode (requires --debug)
- `--init-params-encoded`: Base64 encoded init params
- `--init-params`: List of init params in format `<path>:<attest>:<encrypt>:<type>:<value>`
- `--kms-endpoint`: Kms key gen endpoint (default: http://image-v2.kms.box:1101)
- `--docker-compose`: Path to custom docker-compose.yml file

- `--pcr0` (-0): PCR0 value
- `--pcr1` (-1): PCR1 value
- `--pcr2` (-2): PCR2 value
OR
- `--pcr-preset`: Use predefined PCR values for known images. Possible values: ["base/blue/v1.0.0/amd64", "base/blue/v1.0.0/arm64"]
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

### Example

```bash
# Check system requirements (optional)
./oyster-cvm doctor --check-docker --check-nix
# Sample output:
[INFO] Docker is installed ✓
[INFO] Nix is installed ✓

# Simulate oyster-cvm environment locally
./oyster-cvm simulate \
  --docker-compose ./docker-compose.yml \
  --init-params secret:1:0:utf8:hello

# Sample Output:
[INFO] Simulating oyster local dev environment with:
[INFO]   Platform: amd64
[INFO]   Docker compose: ./docker-compose.yml
[INFO]   Init params: secret:1:0:utf8:hello
[INFO] Pulling dev base image to local docker daemon
...
[INFO] digest path="secret" should_attest=true
[INFO] Starting the dev container with user specified parameters
...
[INFO] Dev container exited with status: exit status: 130
[INFO] Max container CPU usage: 6.65%
[INFO] Max container Memory usage: 40.41 MiB

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
  --pcr-preset "base/blue/v1.0.0/amd64"

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

```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
