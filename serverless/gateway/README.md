![Marlin Oyster Logo](./logo.svg)

# Oyster Serverless Gateway

Monitors jobs on Request Chains and transfers them to the Common Chain for Executors to process. Once Executors respond to the jobs on the Common Chain, the Gateway forwards the responses back to the original Request Chain.

## Build
```
cargo build --target x86_64-unknown-linux-musl
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.serverless.gateway.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

# Dev Setup

- Clone the repository.
- Build the binary -
  ```
  cargo build --target x86_64-unknown-linux-musl
  ```
- Run the binary -
  ```
  ./target/x86_64-unknown-linux-musl/release/serverless-gateway --vsock-addr 1:6000
  ```
- Update the config with the contract addresses -
  ```json
  {
    "common_chain_id": 31337,
    "common_chain_http_url": "http://127.0.0.1:8545/",
    "common_chain_ws_url": "ws://127.0.0.1:8545/",
    "gateways_contract_addr": "0x610178dA211FEF7D417bC0e6FeD39F05609AD788",
    "gateway_jobs_contract_addr": "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
    "enclave_secret_key": "./enclave_secret_key",
    "epoch": 1718602200,
    "time_interval": 20,
    "offset_for_epoch": 4,
    "gateways_start_block": 0
  }
  ```
  `gateways_start_block` is the block the gateway starts reading the `Gateways` contract events from. Set it to the block the `Gateways` contract was deployed at. The events are read in queries of 50,000 blocks, so with `0` on a public chain the gateway has to make several thousand queries before it can relay jobs, and it logs a warning at start-up.

# Dev Run

- Initialize the gateway with owner address, gas wallet private key, web socket api key, list of request chain ID and generate the signatures for registration. For generating `gateway-vsock-client`, follow the [README](../http-on-vsock-client/README.md)
  ```shell
  ./gateway-vsock-client --url vsock://1:6000/ --owner-address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --gas-key 5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a --ws-api-key "" -c 31337
  ```
- Use the signature from the above output to register on the commmon chain and request chain

- Verify the addresses on the gateway by checking the output of above command

## Restarts

The owner address, the gas wallet key and the web socket api key are only kept in memory, they are not written to disk. After the gateway process restarts, inject them again with the same command as above. The enclave key does not change when only the gateway process restarts, so the enclave is still registered on chain.

Once both configs are injected, the gateway reads the registration of its enclave address from the `Gateways` contract on the common chain (owner and request chain ids) and from the `Relay` contract on each request chain. If the enclave is registered with the injected owner on all of them, the gateway starts serving again without a new registration. `/signed-registration-message` runs the same check first, so the command above, which requests a registration message after injecting the configs, gets the answer that the enclave is already registered. A draining state set on chain applies as before, it is read from the `Gateways` contract like the state of the other gateways. If the enclave is not registered, or is registered with another owner or only on some of the chains, the gateway logs it and waits for a registration as on a fresh start. RPC errors during this check are retried with a backoff.

The host can do the injection automatically, for example with a service that waits for the vsock server of the gateway to answer and then runs the `gateway-vsock-client` command above with the same owner address, gas key and api key, and that runs again whenever the gateway process restarts. The gas key then has to be available on the host to that service. This repository does not include such a service.

# Running Tests

```shell
cargo test
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
