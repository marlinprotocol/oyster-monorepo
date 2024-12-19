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
sudo ./cgroupv2_setup.sh
```
To check whether the cgroups were successfully created or not on your system, verify that the output of `ls /sys/fs/cgroup` contains folders `workerd_*`(specifically 20 according to current setup).

<b>Signer file setup</b>

A signer secret is required to run the serverless executor applicaton. It'll also be the identity of the executor enclave on chain i.e, the enclave address will be derived from the corresponding public key. The signer must be a `secp256k1` binary secret.
The <a href="https://github.com/marlinprotocol/keygen">Keygen repo</a> can be used to generate this.

<b> RPC and smart contracts configuration</b>

To run the serverless executor, details related to RPC like the HTTP and WebSocket URLs will be needed through which the executor will communicate with the common chain. Also the addresses of the relevant smart contracts deployed there like **Executors**, **Jobs** and **UserCode** will be needed.

<b>Run the serverless executor application :</b>

```
./target/x86_64-unknown-linux-musl/release/oyster-serverless-executor --help
Usage: oyster-serverless-executor [OPTIONS]

Options:
      --port <PORT>                [default: 6001]
        Server port
      --config-file <CONFIG_FILE>  [default: ./oyster_serverless_executor_config.json]
        Path to the executor configuration parameters file
  -h, --help                       Print help
  -V, --version                    Print version
```
Configuration file parameters required for running an executor node:
```
{
    "workerd_runtime_path": // Runtime path where code and config files will be created and executed (workerd binary should be present here),
    "common_chain_id": // Common chain id,
    "http_rpc_url": // Http url of the RPC endpoint,
    "web_socket_url": // Websocket url of the RPC endpoint,
    "executors_contract_addr": // Executors smart contract address on common chain,
    "jobs_contract_addr": // Jobs smart contract address on common chain,
    "code_contract_addr": // User code calldata smart contract address on common chain,
    "enclave_signer_file": // path to enclave secp256k1 private key file,
    "execution_buffer_time": // Execution buffer time as configured on common chain (in seconds),
    "num_selected_executors": // Number of executors selected at a time to execute a job as configured on common chain
}
```
Example command to run the executor locally:
```
sudo ./target/x86_64-unknown-linux-musl/release/oyster-serverless-executor --port 6001 --config-file ./oyster_serverless_executor_config.json
```

<b> Inject immutable configuration parameters into the application: </b>

Currently there is only one such parameter and it is the address of the executor enclave owner.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"owner_address_hex": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}' <executor_node_ip:executor_node_port>/immutable-config
Immutable params configured!
```

<b> Inject mutable configuration parameters into the application: </b>

Currently there is only one such parameter and it is the gas private key used by the executor enclave to send transactions to the common chain.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"gas_key_hex": "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"}' <executor_node_ip:executor_node_port>/mutable-config
Mutable params configured!
```
<b> The owner can use the below endpoint to get details about the state of the executor node: </b>
```
$ curl <executor_node_ip:executor_node_port>/executor-details
{"enclave_address":"0x2e5e17c117efeb0727765988b230c4d95f8e8c9c","enclave_public_key":"0x2772e3e5d5dfb8e583feb6f4d251f4bda32ef692aad0831055a663d9be3edb4591cc0109d9e8d0672f8576160cf81ed4909b0a0a163951341f74aec44018ea49","gas_address":"0x90f79bf6eb2c4f870365e785982e1f101e93b906","owner_address":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}
```

<b> Exporting registration details from the executor node: </b>

The owner can hit the below endpoint to get the registration details required to register the executor enclave on the common chain **Executors** contract. The endpoint will also start the listening of such event notifications on the common chain inside the enclave node.
```
$ curl <executor_node_ip:executor_node_port>/signed-registration-message
{"job_capacity":20,"owner":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","sign_timestamp":1721388963,"signature":"19902ff8f70d7bba8d0001f619eb5c67bf1a97f8ed0b45fdba1b64a5a25dac5c1e253b533a06f477f7e7673a8ad1875dd415ed01640813a0a5f88723bbb2d8e51b"}
```

**Note:** After the owner will register the executor enclave on the common chain, the node will listen to that event and start the listening of job requests created by the **Jobs** contract on the common chain and execute them acordingly.

## Tests

Before running the tests, generate the cgroups (if not already) and enable the below flag:
```
sudo ./cgroupv2_setup.sh
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
