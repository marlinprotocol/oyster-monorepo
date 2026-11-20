![Marlin Oyster Logo](./logo.svg)

# Serverless Executor

Oyster Serverless Executor is a cutting-edge, high-performance serverless computing platform designed to securely execute JavaScript (JS) code in a highly controlled environment. It is an integral part of the Oyster-Serverless web3 ecosystem used to run dApps via interaction with smart contracts. Executor node is meant to run inside on-chain verified (Oyster-verification protocol) enclave ensuring that any message signed by it will be treated as truth and smart contracts can execute based on that signed message. The owners provide computation services and manage the lifecycle of multiple executor enclaves, like registration, deregistration, stakes etc. Built using the Rust, Actix Web framework and ethers library - Oyster serverless executor leverages the power and security of AWS Nitro Enclaves, Cloudflare workerd runtime, cgroups to provide unparalleled isolation and protection for the executed code and RPCs to interact with the smart contracts.

## Build

<b>Install the following packages : </b>

* build-essential
* libc++1
* cgroup-tools
* libssl-dev
* musl-tools
* make
* pkg-config

`Note : Oyster serverless executor only works on Ubuntu 22.04 and newer versions due to limitations in the workerd dependency.`

<b> Build the executor binary </b>

Build the binary executable:
```
cargo build --release
```
OR (for custom targets)
```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.serverless.executor.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

<b>cgroups v2 setup</b>
```
sudo ../executor-enclave/cgroupv2_setup.sh
```
To check whether the cgroups were successfully created or not on your system, verify that the output of `ls /sys/fs/cgroup` contains folders `workerd_*`(specifically 20 according to current setup).

<b>Signer file setup</b>

A signer secret is required to run the serverless executor application. It'll also be the identity of the executor enclave on chain i.e, the enclave address will be derived from the corresponding public key. The signer must be a `secp256k1` binary secret.
The <a href="https://github.com/marlinprotocol/oyster-monorepo/tree/master/initialization/keygen">Keygen repo</a> can be used to generate this.

<b> RPC and smart contracts configuration</b>

To run the serverless executor, details related to RPC like the HTTP and WebSocket URLs will be needed through which the executor will communicate with the common chain. Also the addresses of the relevant smart contracts deployed there like **Executors**, **Jobs** and **UserCode** will be needed.

<b>Run the serverless executor application :</b>

```
./target/x86_64-unknown-linux-musl/release/oyster-serverless-executor --help
Usage: oyster-serverless-executor [OPTIONS] --vsock-addr <VSOCK_ADDR>

Options:
  -v, --vsock-addr <VSOCK_ADDR>    vsock address to listen on <cid:port>
      --config-file <CONFIG_FILE>  [default: ./oyster_serverless_executor_config.json]
  -h, --help                       Print help
  -V, --version                    Print version
```
Configuration file parameters required for running an executor node:
```
{
  "workerd_runtime_path": // Runtime path where code and config files will be created and executed (workerd binary should be present here),
  "secret_store_path": // Secret store path where secret files are stored
  "common_chain_id": // Common chain id,
  "http_rpc_url": // Http url of the RPC endpoint,
  "web_socket_url": // Websocket url of the RPC endpoint,
  "executors_contract_addr": // Executors smart contract address on common chain,
  "jobs_contract_addr": // Jobs smart contract address on common chain,
  "code_contract_addr": // User code calldata smart contract address on common chain,
  "enclave_signer_file": // path to enclave secp256k1 private key file,
  "execution_buffer_time": // Execution buffer time as configured on common chain (in seconds),
  "num_selected_executors": // Number of executors selected at a time to execute a job as configured on common chain,
  "logs_backfill_chunk_size": // (Optional, default 10000) Maximum block range of a single 'eth_getLogs' query, lower it if the RPC provider limits the range
}
```
Example command to run the executor locally:
```
sudo ./target/x86_64-unknown-linux-musl/release/oyster-serverless-executor --vsock-addr 1:6000 --config-file ./oyster_serverless_executor_config.json
```

<b> Initialize executor with owner address, gas wallet private key, web socket api key and generate the registration signatures </b>

For generating `executor-vsock-client`, follow the [README](../http-on-vsock-client/README.md)
```shell
./executor-vsock-client --url vsock://1:6000/ --owner-address {ENCLAVE_OWNER_ADDRESS} --executor-gas-key {EXECUTOR_GAS_KEY} --store-gas-key {SECRET_STORE_GAS_KEY} --ws-api-key ""
```
This will also start the listening of registration event notifications on the common chain inside the enclave node.

**Note:** After the owner will register the executor enclave on the common chain, the node will listen to that event and start the listening of job requests created by the **Jobs** contract on the common chain and execute them accordingly.

<b> Restarts of the executor process </b>

The owner address and the gas wallet private key are kept in memory only, the executor never writes them to disk. After the executor process restarts (for example `supervisord` restarting it inside the enclave), it does not listen to job requests until the host injects them again. Run the same `executor-vsock-client` command again for that. Once both are injected, the executor reads its entry in the **Executors** contract: if the enclave is already registered, it resumes listening to job requests right away (in draining mode if the executor is draining on chain) instead of waiting for a new registration. The registration signature printed by the client is not needed in that case. The owner is set on chain at registration and cannot change, so if the injected owner differs from the owner in the **Executors** contract, the executor logs a warning with both addresses and continues with the owner from the contract. Fix the owner address in the host config in that case.

Running the client again against an executor that is already configured changes nothing: the owner cannot be changed (the request is rejected), and the gas key and web socket api key are replaced by the same values. So the host can re-inject automatically by running the client periodically, for example from a systemd service with `Restart=always` running:
```shell
while true; do
  ./executor-vsock-client --url vsock://{ENCLAVE_CID}:900/ --owner-address "$OWNER_ADDRESS" --executor-gas-key "$EXECUTOR_GAS_KEY" --ws-api-key "$WS_API_KEY" > /dev/null
  sleep 60
done
```
Keep the variables in an `EnvironmentFile` readable only by the service user rather than in the unit file itself. A restart of the whole enclave generates a new enclave key, so it needs a new registration.

## Tests

Before running the tests, generate the cgroups (if not already) and enable the below flag:
```
sudo ../executor-enclave/cgroupv2_setup.sh
export RUSTFLAGS="--cfg tokio_unstable"
```
The tests need root privileges internally. They should work as long as the shell has sudo cached, a simple `sudo echo` will ensure that.
```
sudo echo && cargo test -- --test-threads 1
```
To run a particular test *test_name* :
```
sudo echo && cargo test 'test name' -- --nocapture &
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
