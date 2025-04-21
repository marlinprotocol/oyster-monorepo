![Marlin Oyster Logo](./logo.svg)

# KMS Derive Server - Mock

The KMS Derive Server Mock provides derivation endpoints to derive secrets using a constant zero seed. It is meant to be mainly used for testing in local enclaves and used by applications there to derive secrets like wallets.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.derive-server-mock.<output>
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
$ ./target/release/kms-derive-server-mock --help
Usage: kms-derive-server-mock [OPTIONS]
Options:
      --listen-addr <LISTEN_ADDR>  Listening address [default: 127.0.0.1:1100]
  -h, --help                       Print help
  -V, --version                    Print version
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
