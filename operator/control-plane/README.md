![Marlin Oyster Logo](./logo.svg)

# Control Plane

The control plane listens to Market contract events and automatically manages infrastructure for Oyster enclaves. A server and a properly set up AWS account is required to run the control plane, see the [provider documentation](https://docs.marlin.org/run-your-own-node/oyster/quickstart/) for more information on the prerequisites and where it fits in the broader picture.

The control plane manages EC2 instances and Elastic IPs. All resources are tagged with the following fields to make them easy to identify and manage without conflicts:
- `managedBy`, set to `marlin`
- `project`, set to `oyster`
- `jobId`, set to the job id that the instance is serving
- `operator`, set to the `provider` cli parameter
- `chainID`, set to the chain ID of the `rpc` cli parameter
- `contractAddress`, set to the `contract` cli parameter

Be careful using one or more of the same tags for any other instances running in the account, it might interfere with proper operation of the contol plane.
 
## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using a Rust Docker image to standardize the build environment:

```bash
# For amd64
docker run --rm -v `pwd`:/code rust@sha256:ed7795c6eaccae53be35939e883e8c3de0197b21e8eddbd9f04b0c4bc757c094 /code/build-amd64.sh

# For arm64
docker run --rm -v `pwd`:/code rust@sha256:c428882ff081342a9661fb13a1d059ecdc0b6e979ffec64b80371cf20a2088b0 /code/build-arm64.sh
```

Expected sha256 checksums are available along with the links to the prebuilt binaries.

## Prebuilt binaries

amd64: https://artifacts.marlin.org/oyster/binaries/control-plane_v2.4.0_linux_amd64 \
checksum: 51934d1b4124c79dbc09bbcb409957d10a1d5f52e12e5dbdf56a9e6ada065b7b

arm64: https://artifacts.marlin.org/oyster/binaries/control-plane_v2.4.0_linux_arm64 \
checksum: 819d09e91ccb8a7ef2d0717cc08759b428ff655378dcc264eb7703ab9cf92ab1

## Usage

```
$ ./target/release/control-plane --help
Control plane for Oyster

Usage: control-plane [OPTIONS] --profile <PROFILE> --key-name <KEY_NAME> --rpc <RPC> --rates <RATES> --bandwidth <BANDWIDTH> --contract <CONTRACT> --provider <PROVIDER>

Options:
      --profile <PROFILE>
          AWS profile
      --key-name <KEY_NAME>
          AWS keypair name
      --regions <REGIONS>
          AWS regions [default: us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,sa-east-1,eu-north-1,eu-west-3,eu-west-2,eu-west-1,eu-central-1,eu-central-2,eu-south-1,eu-south-2,me-south-1,me-central-1,af-south-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-east-1]
      --rpc <RPC>
          RPC url
      --rates <RATES>
          Rates location
      --bandwidth <BANDWIDTH>
          Bandwidth Rates location
      --contract <CONTRACT>
          Contract address
      --provider <PROVIDER>
          Provider address
      --blacklist <BLACKLIST>
          Blacklist location [default: ]
      --whitelist <WHITELIST>
          Whitelist location [default: ]
      --address-blacklist <ADDRESS_BLACKLIST>
          Address Blacklist location [default: ]
      --address-whitelist <ADDRESS_WHITELIST>
          Address Whitelist location [default: ]
      --port <PORT>
          Metadata server port [default: 8080]
  -h, --help
          Print help
  -V, --version
          Print version
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
