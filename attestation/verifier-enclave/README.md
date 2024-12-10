![Marlin Oyster Logo](./logo.svg)

# Attestation Verifier Enclave

The attestation verifier enclave packages the [attestation verifier](https://github.com/marlinprotocol/oyster-attestation-verifier) along with related services in an enclave.

The attestation verifier enclave is built using Nix for reproducibility. It does NOT use the standard `nitro-cli` based pipeline, and instead uses [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) in order to produce bit-for-bit reproducible enclaves.

## Build

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.attestation.verifier-enclave.default
```

Supported flavors:
- `gnu`
- `musl`

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
