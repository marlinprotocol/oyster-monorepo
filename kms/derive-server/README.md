![Marlin Oyster Logo](./logo.svg)

# KMS Derive Server

The KMS Derive Server provides derivation endpoints to derive secrets. It is meant to be run inside an enclave and used by enclave application to derive secrets like wallets.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.derive-server.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```
$ ./target/release/kms-derive-server --help
Usage: kms-derive-server [OPTIONS]

Options:
      --kms-endpoint <KMS_ENDPOINT>
          KMS endpoint
      --kms-pubkey <KMS_PUBKEY>
          KMS X25519 pubkey, hex encoded
      --listen-addr <LISTEN_ADDR>
          Listening address [default: 127.0.0.1:1100]
      --attestation-endpoint <ATTESTATION_ENDPOINT>
          Attestation endpoint [default: http://127.0.0.1:1301/attestation/raw]
      --secret-path <SECRET_PATH>
          Path to X25519 secret file [default: /app/x25519.sec]
      --contract-address-file <CONTRACT_ADDRESS_FILE>
          file containing enclave verification contract address in hexadecimal
      --root-server-config <ROOT_SERVER_CONFIG>
          JSON config file containing the root server's details
  -h, --help
          Print help
  -V, --version
          Print version
```

## Endpoints

### Derive

#### Endpoint

`/derive`

#### Usage

```
GET /derive?path=<path>

<binary data of the derived key in response>
```

### Derive secp256k1 key (Ethereum wallet)

#### Endpoint

`/derive/secp256k1`

#### Usage

```
GET /derive/secp256k1?path=<path>

<binary data of the derived key in response>
```

### Derive ed25519 key (Solana wallet)

#### Endpoint

`/derive/ed25519`

#### Usage

```
GET /derive/ed25519?path=<path>

<binary data of the derived key in response>
```

### Derive x25519 key

#### Endpoint

`/derive/x25519`

#### Usage

```
GET /derive/x25519?path=<path>

<binary data of the derived key in response>
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
