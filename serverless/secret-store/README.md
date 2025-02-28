![Marlin Oyster Logo](./logo.svg)

# Secret store

Oyster Secret Store is a platform designed to securely store user secrets in a highly controlled environment. It is a part of the Oyster web3 ecosystem used to store secret data the users might want to use to run their code on Serverless network. Secret store node is meant to run inside on-chain verified (Oyster-verification protocol) enclave ensuring that any message signed by it will be treated as truth and smart contracts can execute based on that signed message. The owners provide computation services and manage the lifecycle of multiple secret store enclaves, like registration, deregistration, stakes etc. Built using the Rust, Actix Web framework and alloy library - Oyster secret store leverages the power and security of AWS Nitro Enclaves to provide unparalleled isolation and protection for the stored secrets and RPCs to interact with the smart contracts.

## Build

<b>Install the following packages : </b>

* build-essential
* libc++1
* libssl-dev
* musl-tools
* make
* pkg-config

<b> Build the secret store binary </b>

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
nix build -v .#<flavor>.serverless.secret-store.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

<b>Signer file setup</b>

A signer secret is required to run the secret store applicaton. It'll also be the identity of the store enclave on chain i.e, the enclave address will be derived from the corresponding public key. The signer must be a `secp256k1` binary secret.
The <a href="https://github.com/marlinprotocol/oyster-monorepo/tree/master/initialization/keygen">Keygen repo</a> can be used to generate this.

<b> RPC and smart contracts configuration</b>

To run the secret store, details related to RPC like the HTTP and WebSocket URLs will be needed through which the store will communicate with the common chain. Also the addresses of the relevant smart contracts deployed there like **SecretStore** and **SecretManager** will be needed.

<b>Run the secret store application :</b>

```
./target/x86_64-unknown-linux-musl/release/oyster-secret-store --help
Usage: oyster-secret-store [OPTIONS]

Options:
      --external-port <PORT>                [default: 6002]
        External port to expose outside enclave for injecting secret
      --config-file <CONFIG_FILE>  [default: ./oyster_secret_store_config.json]
        Path to the configuration parameters file
  -h, --help                       Print help
  -V, --version                    Print version
```
Configuration file parameters required for running a secret store node:
```
{
  "config_port": // Secret store configuration port to inject parameters and export registration details
  "secret_store_path": // Directory path where the secret data files will be created and stored,
  "common_chain_id": // Common chain id,
  "http_rpc_url": // Http url of the RPC endpoint,
  "web_socket_url": // Websocket url of the RPC endpoint,
  "tee_manager_contract_addr": // TeeManager smart contract address on common chain,
  "secret_manager_contract_addr": // SecretManager smart contract address on common chain,
  "enclave_signer_file": // path to enclave secp256k1 private key file,
  "acknowledgement_timeout": // Secret inject acknowledgement timeout as configured on common chain (in seconds),
  "mark_alive_timeout": // Secret Store mark alive timeout as configured on common chain (in seconds),
  "num_selected_stores": // Number of stores selected to store an user secret as configured on common chain
}
```
Example command to run the secret store locally:
```
sudo ./target/x86_64-unknown-linux-musl/release/oyster-secret-store --external-port 6002 --config-file ./oyster_secret_store_config.json
```

<b> Inject immutable configuration parameters into the application: </b>

Currently there is only one such parameter and it is the address of the secret store enclave owner.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"owner_address_hex": "{OWNER_ADDRESS_HEX}"}' <secret_store_node_ip:secret_store_node_port>/immutable-config
Immutable params configured!
```

<b> Inject mutable configuration parameters into the application: </b>

Currently there are 2 such parameters - Gas private key used by the secret store enclave to send transactions to the common chain, and Alchemy API key for the web socket connection to the common chain.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"gas_key_hex": "{GAS_PRIVATE_KEY_HEX}", "ws_api_key": "{ALCHEMY_API_KEY}"}' <secret_store_node_ip:secret_store_node_port>/mutable-config
Mutable params configured!
```

<b> The owner can use the below endpoint to get details about the state of the secret store node: </b>
```
$ curl <secret_store_node_ip:secret_store_node_port>/store-details
{"enclave_address":"{ENCLAVE_ADDRESS}","enclave_public_key":"{ENCLAVE_PUBLIC_KEY_HEX}","gas_address":"{ENCLAVE_GAS_ADDRESS}","owner_address":"{ENCLAVE_OWNER_ADDRESS}"}
```

<b> Exporting registration details from the secret store node: </b>

The serverless executor service will request the below endpoint to get the registration details required to register the whole TEE enclave on the common chain **TeeManager** contract. This endpoint will also start the listening of such event notifications from the common chain inside the secret store service.
```
$ curl <secret_store_node_ip:secret_store_node_port>/register-details
{"storage_capacity":{SECRET_STORE_CAPACITY_BYTES}}
```

**Note:** After the owner will register the secret store enclave on the common chain, the node will listen to that event and start the listening of user secret requests created by the **SecretManager** contract on the common chain and store/modify them accordingly.

<b> Injecting secret data into the secret store node: </b>

User after receiving the IP address and public key of the secret store enclaves selected to store their secret can use the below endpoint to inject their encrypted and signed secret data into a secret store node and retrieve the enclave secret stored acknowledgement details.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"secret_id": {ASSIGNED_SECRET_ID}, "encrypted_secret_hex": "{ENCRYPTED_SECRET_DATA_BYTES_HEX}", "signature_hex": "{USER_SIGNATURE_OF_SECRET_DETAILS}"}' <secret_store_node_ip:secret_store_node_port>/inject-secret
{"secret_id":{SECRET_ID},"sign_timestamp":"{SIGN_TIMESTAMP}","signature":"{ENCLAVE_SIGNATURE_OF_SECRET_ACKNOWLEDGEMENT}"}
```

<b> Encrypting secret data and signing it: </b>

User can use the following binary to encrypt their secret data bytes with the selected secret store enclave's public key, sign it using their private key with which they requested storage on the common chain and inject the secret into the secret stores. 
```
$ ./target/x86_64-unknown-linux-musl/release/oyster-secret-user-utility --secret-data-hex {SECRET_DATA_BYTES_HEX} --user-private-hex {USER_PRIVATE_KEY_HEX} --http-rpc-url {COMMON_CHAIN_HTTP_RPC_URL} --config-file {SECRET_STORE_ENCLAVES_INFO_JSON} --txn-hash {SECRET_CREATE_TRANSACTION_HASH}
Secret injected successfully into enclave "{ENCLAVE_ADDRESS}" with acknowledgement: Object {"secret_id": String("{SECRET_ID}"), "sign_timestamp": Number({ENCLAVE_SIGN_TIMESTAMP}), "signature": String("{ENCLAVE_ACKNOWELDGEMENT_SIGNATURE}")}
...
```
The "SECRET_STORE_ENCLAVES_INFO_JSON" will look something like this: 
```
{
    "stores": {
        "{ENCLAVE_ADDRESS}": {
            "public_key": "{ENCLAVE_PUBLIC_KEY}",
            "store_external_ip": "http://{ENCLAVE_PUBLIC_IP}:{EXTERNAL_PORT}"
        },
        ...
    }
}
```


## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
