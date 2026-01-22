![Marlin Oyster Logo](./logo.svg)

# Oyster Indexer

This repository contains an indexer for the Oyster marketplace contract.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Usage

### Environment file

The indexer relies on an environment file to provide parameters containing secrets. An example .env file is provided along with the repository. It has two parameters:

- `DATABASE_URL`: production database URL where the indexer stores indexed data. It should look like `postgres://<username>:<password>@<host>/<database>`.
- (Optional) `TEST_DATABASE_URL`: database URL for running tests. The format is the same as `DATABASE_URL`, the user must have permissions to create new databases on the server since the tests each create a new database for isolation.

### Run

```bash
$ ./target/release/oyster-indexer --help
Usage: oyster-indexer [OPTIONS] --rpc <RPC> --contract <CONTRACT> --start-block <START_BLOCK>

Options:
  -r, --rpc <RPC>                  RPC URL
  -c, --contract <CONTRACT>        Market contract
  -s, --start-block <START_BLOCK>  Start block for log parsing
      --range-size <RANGE_SIZE>    Size of block range for fetching logs [default: 2000]
  -h, --help                       Print help
  -V, --version                    Print version
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
