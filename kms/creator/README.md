![Marlin Oyster Logo](./logo.svg)

# KMS Creator

The KMS Creator generates encrypted randomness with two goals:
- It is verifiable that the encrypted randomness was generated inside a Creator enclave, even after the enclave is terminated.
- The encrypted randomness can be decrypted by KMS root server enclaves.

The first goal is achieved by the creator attaching a signature to the encrypted randomness whose private key is generated inside the enclave and public key is present in remote attestations. Once generated, the randomness, signature and a remote attestation can be preserved indefinitely as proof.

The second goal is achieved through the condition parameter. It attaches a decryption condition to the encrypted randomness that allows the creator to restrict who can decrypt it. In the common case, this would be checking if an address is approved by the [KmsRoot](../../contracts/contracts-foundry/src/kms/KmsRoot.sol) smart contract that verifies remote attestations before approving KMS root servers.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.creator.<output>
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
$ ./target/release/kms-creator --help
Usage: kms-creator [OPTIONS] --condition <CONDITION> --dkg-public-key <DKG_PUBLIC_KEY>

Options:
      --listen-addr <LISTEN_ADDR>
          DKG listening address [default: 0.0.0.0:1100]
      --signer <SIGNER>
          Path to file with private key signer [default: /app/secp256k1.sec]
      --condition <CONDITION>
          Condition string for the key
      --dkg-public-key <DKG_PUBLIC_KEY>
          DKG ceremony public key
  -h, --help
          Print help
  -V, --version
          Print version
```

## Example

```
$ curl <ip:port>/generate
544d4b69000100009293c43099822c1c52b001c0a...
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
