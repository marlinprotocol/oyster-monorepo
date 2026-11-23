![Marlin Oyster Logo](./logo.svg)

# Serverless Executor Enclave

The serverless executor enclave packages the [serverless executor](https://github.com/marlinprotocol/oyster-monorepo/tree/master/serverless/executor) along with related services in an enclave.

The serverless executor enclave is built using Nix for reproducibility. It does NOT use the standard `nitro-cli` based pipeline, and instead uses [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) in order to produce bit-for-bit reproducible enclaves.

## Build

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.serverless.executor-enclave.default
```

Supported flavors:
- `gnu`
- `musl`

## Config

The executor config, `oyster_serverless_executor_config.json`, is built into the enclave image, so changing it changes the image id.

`jobs_contract_addr` and `executors_contract_addr` are placeholders in the committed config. Set them to the `Jobs` and `Executors` contracts of the serverless deployment the executor is for before building. The executor does not start with the placeholders, it exits with an error about the config file.

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
