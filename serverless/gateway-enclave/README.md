![Marlin Oyster Logo](./logo.svg)

# Serverless Gateway Enclave

The serverless gateway enclave packages the [serverless gateway](https://github.com/marlinprotocol/oyster-monorepo/tree/master/serverless/gateway) along with related services in an enclave.

The serverless gateway enclave is built using Nix for reproducibility. It does NOT use the standard `nitro-cli` based pipeline, and instead uses [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) in order to produce bit-for-bit reproducible enclaves.

## Build

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.serverless.gateway-enclave.default
```

Supported flavors:
- `gnu`
- `musl`

## Config

The gateway config, `oyster_serverless_gateway_config.json`, is built into the enclave image, so changing it changes the image id.

Set `gateways_start_block` to the block the `Gateways` contract was deployed at before building. It is `0` in the committed config, which makes the gateway read the contract events from the first block of the chain. That works, but on a public chain the first scan is several thousand `eth_getLogs` queries and the gateway does not relay jobs until it is done.

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
