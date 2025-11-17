![Marlin Oyster Logo](./logo.svg)

# Oyster Arbitrum One Market Indexer

This repository contains an indexer for the Oyster marketplace contract on Arb one chain, meant to be utilized for operator control-plane DB.

## Build

```bash
cargo build --release
```

## Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.operator.arb-indexer.<output>
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
$ ./target/release/oyster-operator-arb-indexer --help
Usage: oyster-operator-arb-indexer [OPTIONS] --rpc <RPC> --contract <CONTRACT> --provider <PROVIDER>

Options:
  -r, --rpc <RPC>                  Websocket RPC URL
  -c, --contract <CONTRACT>        Market contract address
  -p, --provider <PROVIDER>        Provider address
  -s, --start-block <START_BLOCK>  Start block for log parsing
      --range-size <RANGE_SIZE>    Size of block range for fetching logs [default: 500]
  -h, --help                       Print help
  -V, --version                    Print version
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
