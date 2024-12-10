![Marlin Oyster Logo](./logo.svg)

# Iperf3 Enclave

The iperf3 enclave packages iperf3 along with related services in an enclave for benchmarking networking throughput. Both Salmon and Tuna images are provided.

The enclave is built using nix for reproducibility. It does NOT use the standard `nitro-cli` based pipeline, and instead uses [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) in order to produce bit-for-bit reproducible enclaves.

## Build

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.networking.iperf3-enclave.<family>.default
```

Supported flavors:
- `gnu`
- `musl`

Supported families:
- `salmon`
- `tuna`

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
