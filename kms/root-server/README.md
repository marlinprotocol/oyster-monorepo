![Marlin Oyster Logo](./logo.svg)

# KMS Root Server

The KMS Root Server provides derivation endpoints to derive secrets and/or corresponding public keys. The root seed is provided through a file containing randomenss encrypted against a DKG key.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.root-server.<output>
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
$ ./target/release/kms-root-server --help
Usage: kms-root-server [OPTIONS]

Options:
      --randomness-file <RANDOMNESS_FILE>
          Path to encrypted randomness file [default: /app/init-params]
      --scallop-listen-addr <SCALLOP_LISTEN_ADDR>
          Scallop listening address [default: 0.0.0.0:1100]
      --public-listen-addr <PUBLIC_LISTEN_ADDR>
          Public listening address [default: 0.0.0.0:1101]
      --signer <SIGNER>
          Path to file with private key signer [default: /app/secp256k1.sec]
      --porter <PORTER>
          Porter URI [default: https://porter.nucypher.io/decrypt]
      --ritual <RITUAL>
          Ritual id [default: 40]
      --coordinator <COORDINATOR>
          Coordinator address [default: 0xE74259e3dafe30bAA8700238e324b47aC98FE755]
      --rpc <RPC>
          RPC URL [default: https://polygon-rpc.com]
      --attestation-endpoint <ATTESTATION_ENDPOINT>
          Attestation endpoint [default: http://127.0.0.1:1301/attestation/raw]
      --secret-path <SECRET_PATH>
          Path to X25519 secret file [default: /app/x25519.sec]
      --threshold <THRESHOLD>
          DKG threshold [default: 16]
      --delay <DELAY>
          Initial delay to allow for attestation verification [default: 1800]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Scallop endpoints

The root server exposes some endpoints that are only accessible to Scallop-enabled clients. It ensures sharding of the key derivation space based on attestation information so enclaves cannot step over each other and issue themselves secrets meant for other enclaves.

### Derive

#### Endpoint

`/derive`

#### Usage

```
GET /derive

<binary data of the derived key in response>
```

## Public endpoints

Unlike the scallop endpoints, these endpoints are availble to any caller. They are mainly intended to fetch public keys for derivation paths in advance before even running an enclave.

### Derive secp256k1 public key

#### Endpoint

`/derive/secp256k1/public`

#### Usage

```
GET /derive/secp256k1/public?pcr0=<pcr0>&pcr1=<pcr1>&pcr2=<pcr2>&user_data=<user_data>&path=<path>

<binary data of the derived public key in response>
```

### Derive Ethereum address

#### Endpoint

`/derive/secp256k1/address/ethereum`

#### Usage

```
GET /derive/secp256k1/address/ethereum?pcr0=<pcr0>&pcr1=<pcr1>&pcr2=<pcr2>&user_data=<user_data>&path=<path>

0x92148e8f84096d0dfe7e66a025d14d1e2594ddc2
```

### Derive ed25519 public key

#### Endpoint

`/derive/ed25519/public`

#### Usage

```
GET /derive/ed25519/public?pcr0=<pcr0>&pcr1=<pcr1>&pcr2=<pcr2>&user_data=<user_data>&path=<path>

<binary data of the derived public key in response>
```

### Derive Solana address

#### Endpoint

`/derive/ed25519/address/solana`

#### Usage

```
GET /derive/ed25519/address/solana?pcr0=<pcr0>&pcr1=<pcr1>&pcr2=<pcr2>&user_data=<user_data>&path=<path>

BEYzkmcGNdhqHAPKQ7oz89n1RbAumm2kwtX113pPuCax
```

### Derive x25519 public key

#### Endpoint

`/derive/x25519/public`

#### Usage

```
GET /derive/x25519/public?pcr0=<pcr0>&pcr1=<pcr1>&pcr2=<pcr2>&user_data=<user_data>&path=<path>

<binary data of the derived public key in response>
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
