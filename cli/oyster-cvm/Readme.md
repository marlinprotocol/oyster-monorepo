![Marlin Oyster Logo](./logo.svg)

# Oyster CVM CLI

A command line utility to manage Oyster CVM lifecycle: build, upload, deploy and verify. Get started easily with just a `docker-compose` file.

## Prerequisites

- Docker (optional - required only for custom builds)
- Nix (optional - required only for custom builds)
- Git (for fetching flakes)

## Installation

From source:

```bash
git clone https://github.com/marlinprotocol/oyster-monorepo.git
cd cli/oyster-cvm
cargo build --release
```

Supports both Linux and MacOS builds.

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
- `--pcr-preset`: Use predefined PCR values for known images
- `--attestation-port` (-p): Attestation port (default: 1300)
- `--max-age` (-a): Maximum age of attestation in milliseconds (default: 300000)
- `--timestamp` (-t): Attestation timestamp in milliseconds (default: 0)
- `--root-public-key` (-r): Root public key (defaults to AWS root key)

#### `deploy`
Deploys an Oyster CVM instance.

Required args:
- `--wallet-private-key` or `--wallet-private-key-file`: Private key for transaction signing
- `--operator`: Operator address

Optional args:
- `--image-url`: URL of the enclave image (defaults to base image)
- `--region`: Region for deployment (defaults to us-east-1)
- `--instance-type`: Instance type (defaults to m5a.2xlarge)
- `--duration-in-minutes`: Duration in minutes
- `--bandwidth`: Bandwidth in KBps (default: 10)
- `--job-name`: Job name
- `--debug`: Start enclave in debug mode
- `--docker-compose`: Path to custom docker-compose.yml file

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

# Deploy custom image
./oyster-cvm deploy \
  --image-url "ipfs://Qm..." \
  --wallet-private-key-file ./key.txt \
  --operator "0x..." \
  --instance-type "m5a.2xlarge" \
  --duration-in-minutes 60 \
  --bandwidth 200 \
  --job-name "my-custom-job" \
  --debug

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

# Verify an enclave using PCR preset
./oyster-cvm verify \
  --enclave-ip 192.168.1.100 \
  --pcr-preset base-image

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
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
