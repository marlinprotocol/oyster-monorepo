![Marlin Oyster Logo](./logo.svg)

# Control Plane

The control plane listens to Market contract events and automatically manages infrastructure for Oyster enclaves. A server and a properly set up AWS account is required to run the control plane, see the [operator documentation](https://docs.marlin.org/oyster/join/cvm/) for more information on the prerequisites and where it fits in the broader picture.

The control plane manages EC2 instances and Elastic IPs. All resources are tagged with the following fields to make them easy to identify and manage without conflicts:
- `managedBy`, set to `marlin`
- `project`, set to `oyster`
- `jobId`, set to the job id that the instance is serving
- `operator`, set to the `provider` cli parameter
- `chainID`, set to the chain ID of the `rpc` cli parameter
- `contractAddress`, set to the `contract` cli parameter

Be careful using one or more of the same tags for any other instances running in the account, it might interfere with proper operation of the control plane.
 
## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.operator.control-plane.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

### Prebuilt binaries

Prebuilt binaries can be obtained from the following URLs:

amd64: https://artifacts.marlin.org/oyster/binaries/control-plane_v3.0.0_linux_amd64 \
sha256: ff5c58ab5b09e3cd05ffc3d5d6ce65da07aa7529c6868d48a1adb3d301a63e2c

arm64: https://artifacts.marlin.org/oyster/binaries/control-plane_v3.0.0_linux_arm64 \
sha256: 76ce84122aef6963e595621daa84dff0d354fcfe42fc381cfc70cbd1f4e6d752

Built using Nix on the `control-plane-v3.0.0` tag.

## Usage

```
$ ./target/release/control-plane --help
Control plane for Oyster

Usage: control-plane [OPTIONS] --profile <PROFILE> --key-name <KEY_NAME> --db-url <DB_URL> --rates <RATES> --bandwidth <BANDWIDTH> --chain <CHAIN> --contract <CONTRACT> --provider <PROVIDER>

Options:
      --profile <PROFILE>
          AWS profile
      --key-name <KEY_NAME>
          AWS keypair name
      --regions <REGIONS>
          AWS regions [default: us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,sa-east-1,eu-north-1,eu-west-3,eu-west-2,eu-west-1,eu-central-1,eu-central-2,eu-south-1,eu-south-2,me-south-1,me-central-1,af-south-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-east-1]
      --db-url <DB_URL>
          Market DB url
      --rates <RATES>
          Rates location
      --bandwidth <BANDWIDTH>
          Bandwidth Rates location
      --chain <CHAIN>
          Chain ID
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
