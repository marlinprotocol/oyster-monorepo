# Oyster monorepo

Monorepo for the Oyster platform.

## Organization

The repository is organized into projects:

- [attestation/server](./attestation/server/): Attestation server that uses the NSM API to generate attestations.
- [attestation/server-custom](./attestation/server-custom/): Attestation server that uses the NSM API to generate attestations and accepts query parameters for customizing attestation fields.
- [attestation/server-custom-mock](./attestation/server-custom-mock/): Attestation server that uses a local root of trust to generate attestations and accepts query parameters for customizing attestation fields.
- [attestation/verifier](./attestation/verifier/): Attestation verifier server that verifies attestations.
- [attestation/verifier-enclave](./attestation/verifier-enclave/): Attestation verifier enclave that packages the attestation verifier server.
- [attestation/verifier-risczero](./attestation/verifier-risczero/): Attestation verifier that generates a ZK proof of attestation verification using RISCZero.
- [contracts/indexer](./contracts/indexer/): Indexer for the Oyster contracts.
- [initialization/init-server](./initialization/init-server/): Server that provides data endpoints over vsocks during enclave initialization.
- [initialization/vet](./initialization/vet/): Curl-like utility that makes http queries over vsocks instead of TCP sockets.
- [initialization/keygen](./initialization/keygen/): Keypair generators.
- [kernels](./kernels/): Linux kernels for different classes of enclave images and different use cases.
- [networking/tcp-proxy](./networking/tcp-proxy/): TCP proxies that are part of the networking stack of Salmon images.
- [networking/raw-proxy](./networking/raw-proxy/): Raw proxies that are part of the networking stack of Tuna images.
- [networking/iperf3-enclave](./networking/iperf3-enclave/): Enclave image that packages iperf3 for benchmarking purposes.
- [operator/control-plane](./operator/control-plane/): Control plane that manages deployments on behalf of Oyster operators.
- [operator/quota-monitor-aws](./operator/quota-monitor-aws/): Quota monitor to help Oyster operators manage AWS quotas and resource limits.
- [operator/setup-aws](./operator/setup-aws/): Setup repository that helps operators prepare their AWS account for participating in Oyster.
- [sdks/rs](./sdks/rs/): Oyster SDK written in Rust.
- [sdks/go](./sdks/go/): Oyster SDK written in Go.
- [sdks/docker-enclave](./sdks/docker-enclave/): Enclave that allows docker compose based deployment.

In addition, some external projects are used which are described in [external](./external/).

## Project guidelines

Each project is expected to be owned, managed and licensed independently. Here's a quick checklist of items that are expected of every project:

- MUST have a README.md with detailed instructions
  - MUST cover what the project is about
  - MUST cover how to build and/or use it in the context of the monorepo
  - SHOULD cover how to build and/or use it as an independent component outside the monorepo
- MUST have a LICENSE.txt file with an appropriate license
- SHOULD have a Nix build file
- SHOULD be registered in the root flake

## Licensing

Each project picks its own license. Please refer to each project subdirectory for the same. In addition, each project might use external dependencies each of which have their own license.
