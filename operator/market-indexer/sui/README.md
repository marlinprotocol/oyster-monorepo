![Marlin Oyster Logo](./logo.svg)

# Oyster Sui Market Indexer

This repository contains an indexer for the Oyster marketplace contract on Sui chain, meant to be utilized for operator control-plane DB.

## Build

```bash
cargo build --release
```

## Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.operator.sui-indexer.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

### Environment file

The indexer relies on an environment file to provide parameters containing secrets. It has the parameter:

- `DATABASE_URL`: production database URL where the indexer stores indexed data. It should look like `postgres://<username>:<password>@<host>/<database>`.

### Run

```bash
$ ./target/release/oyster-sui-market-indexer --help
Usage: oyster-sui-market-indexer [OPTIONS] --grpc-url <GRPC_URL> --remote-checkpoint-url <REMOTE_CHECKPOINT_URL> --package-id <PACKAGE_ID> --provider <PROVIDER>

Options:
  -g, --grpc-url <GRPC_URL>                            gRPC URL
      --grpc-username <GRPC_USERNAME>                  gRPC URL auth username
      --grpc-password <GRPC_PASSWORD>                  gRPC URL auth password
      --grpc-token <GRPC_TOKEN>                        gRPC URL auth token
  -r, --remote-checkpoint-url <REMOTE_CHECKPOINT_URL>  Remote checkpoint url
  -p, --package-id <PACKAGE_ID>                        Market program package ID
      --provider <PROVIDER>                            Provider address
  -s, --start-block <START_BLOCK>                      Start block for log parsing
      --range-size <RANGE_SIZE>                        Size of block range for fetching logs [default: 500]
  -h, --help                                           Print help
  -V, --version                                        Print version
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
