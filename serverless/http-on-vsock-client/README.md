![Marlin Oyster Logo](./logo.svg)

# HTTP Over Vsock Client
This application serves as a client for HTTP over vsock connections with the Oyster enclave, which runs the server. It
enables operators of Oyster to communicate securely over vsock, providing the same functionality as HTTP.

## Build

```bash
cargo build --release
```

### Reproducible builds
Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used
to trigger builds:

```bash
nix build -v .#<flavor>.serverless.http-on-vsock-client.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```bash
$ ./executor-vsock-client --help
Usage: executor-vsock-client --url <URL> --owner-address <OWNER_ADDRESS> --executor-gas-key <EXECUTOR_GAS_KEY> --store-gas-key <STORE_GAS_KEY> --ws-api-key <WS_API_KEY>

Options:
  -u, --url <URL>                              url to query
  -o, --owner-address <OWNER_ADDRESS>          owner address
  -e, --executor-gas-key <EXECUTOR_GAS_KEY>    executor gas key
  -s, --store-gas-key <STORE_GAS_KEY           secret store gas key
  -w, --ws-api-key <WS_API_KEY>                ws api key
  -h, --help                                   Print help
  -V, --version                                Print version
```

```bash
$ ./gateway-vsock-client --help
Usage: gateway-vsock-client [OPTIONS] --url <URL> --owner-address <OWNER_ADDRESS> --gas-key <GAS_KEY> --ws-api-key <WS_API_KEY>

Options:
  -u, --url <URL>                      url to query
  -o, --owner-address <OWNER_ADDRESS>  owner address
  -g, --gas-key <GAS_KEY>              gas key
  -w, --ws-api-key <WS_API_KEY>        ws api key
  -c, --chain-ids <CHAIN_IDS>          list of chain ids
  -h, --help                           Print help
  -V, --version                        Print version
```

## Example

```bash
$ ./executor-vsock-client --url vsock://88:6000/ --owner-address <OWNER_ADDRESS> --executor-gas-key <EXECUTOR_GAS_KEY> --store-gas-key <STORE_GAS_KEY> --ws-api-key <WS_API_KEY>
```

```bash
$ ./gateway-vsock-client --url vsock://88:6000/ --owner-address <OWNER_ADDRESS> --gas-key <GAS_KEY> --ws-api-key <WS_API_KEY> 31337 -c 421614
```
## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
