{
  nixConfig = {
    extra-substituters = ["https://oyster.cachix.org"];
    extra-trusted-public-keys = ["oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-util = {
      url = "github:monzo/aws-nitro-util";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    naersk,
    nitro-util,
  }: let
    systemBuilder = systemConfig: rec {
      external.dnsproxy = import ./external/dnsproxy.nix {
        inherit nixpkgs systemConfig;
      };
      external.supervisord = import ./external/supervisord.nix {
        inherit nixpkgs systemConfig;
      };
      attestation.server = import ./attestation/server {
        inherit nixpkgs systemConfig fenix naersk;
      };
      attestation.server-custom = import ./attestation/server-custom {
        inherit nixpkgs systemConfig fenix naersk;
      };
      attestation.server-custom-mock = import ./attestation/server-custom-mock {
        inherit nixpkgs systemConfig fenix naersk;
      };
      attestation.server-mock = import ./attestation/server-mock {
        inherit nixpkgs systemConfig fenix naersk;
      };
      attestation.verifier = import ./attestation/verifier {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.init-params-decoder = import ./initialization/init-params-decoder {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.init-server = import ./initialization/init-server {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.keygen = import ./initialization/keygen {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.vet = import ./initialization/vet {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.logger = import ./initialization/logger {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.pcr-utils = import ./initialization/pcr-utils {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kernels.vanilla = import ./kernels/vanilla.nix {
        inherit nixpkgs systemConfig;
      };
      kernels.tuna = import ./kernels/tuna.nix {
        inherit nixpkgs systemConfig;
      };
      kernels.serverless = import ./kernels/serverless.nix {
        inherit nixpkgs systemConfig;
      };
      kms.creator = import ./kms/creator {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.creator-enclave = import ./kms/creator-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
        creator = kms.creator.compressed;
      };
      kms.creator-verifier = import ./kms/creator-verifier {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.derive-server = import ./kms/derive-server {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.derive-server-mock = import ./kms/derive-server-mock {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.derive-server-enclave = import ./kms/derive-server-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
        derive-server = kms.derive-server.compressed;
      };
      kms.root-server = import ./kms/root-server {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.root-server-enclave = import ./kms/root-server-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
        root-server = kms.root-server.compressed;
      };
      kms.root-server-contract = import ./kms/root-server-contract {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kms.root-server-arbone-enclave = import ./kms/root-server-arbone-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
        root-server-contract = kms.root-server-contract.compressed;
      };
      local.dev-image = nixpkgs.legacyPackages.${systemConfig.system}.callPackage ./local/dev-image {
        inherit nixpkgs systemConfig;
        supervisord = external.supervisord.compressed;
        keygen = initialization.keygen.compressed;
        attestation-server-mock = attestation.server-mock.compressed;
        derive-server-mock = kms.derive-server-mock.compressed;
      };
      networking.raw-proxy = import ./networking/raw-proxy {
        inherit nixpkgs systemConfig fenix naersk;
      };
      networking.tcp-proxy = import ./networking/tcp-proxy {
        inherit nixpkgs systemConfig fenix naersk;
      };
      operator.control-plane = import ./operator/control-plane {
        inherit nixpkgs systemConfig fenix naersk;
      };
      operator.setup-aws = import ./operator/setup-aws {
        inherit nixpkgs systemConfig fenix naersk;
      };
      attestation.verifier-enclave = import ./attestation/verifier-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        tcp-proxy = networking.tcp-proxy.compressed;
        attestation-server = attestation.server.compressed;
        attestation-verifier = attestation.verifier.compressed;
        kernels = kernels.vanilla;
      };
      networking.iperf3-enclave.salmon = import ./networking/iperf3-enclave/salmon {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        tcp-proxy = networking.tcp-proxy.compressed;
        attestation-server = attestation.server.compressed;
        kernels = kernels.vanilla;
      };
      networking.iperf3-enclave.tuna = import ./networking/iperf3-enclave/tuna {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
      };
      sdks.docker-enclave = nixpkgs.legacyPackages.${systemConfig.system}.callPackage ./sdks/docker-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        derive-server = kms.derive-server.compressed;
        init-params-decoder = initialization.init-params-decoder.compressed;
        kernels = kernels.tuna;
      };
      enclaves.blue = nixpkgs.legacyPackages.${systemConfig.system}.callPackage ./enclaves/blue {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation.server.compressed;
        vet = initialization.vet.compressed;
        derive-server = kms.derive-server.compressed;
        init-params-decoder = initialization.init-params-decoder.compressed;
        kernels = kernels.tuna;
      };
      cli.oyster-cvm = import ./cli/oyster-cvm {
        inherit nixpkgs systemConfig fenix naersk;
      };
      cli.oyster-serverless = import ./cli/oyster-serverless {
        inherit nixpkgs systemConfig fenix naersk;
      };
      serverless.executor = import ./serverless/executor {
        inherit nixpkgs systemConfig fenix naersk;
      };
      serverless.executor-enclave = import ./serverless/executor-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        tcp-proxy = networking.tcp-proxy.compressed;
        attestation-server = attestation.server.compressed;
        executor = serverless.executor.compressed;
        secret-store = serverless.secret-store.compressed;
        kernels = kernels.serverless;
        workerd = serverless.workerd;
      };
      serverless.gateway = import ./serverless/gateway {
        inherit nixpkgs systemConfig fenix naersk;
      };
      serverless.gateway-enclave = import ./serverless/gateway-enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        keygen = initialization.keygen.compressed;
        tcp-proxy = networking.tcp-proxy.compressed;
        attestation-server = attestation.server.compressed;
        gateway = serverless.gateway.compressed;
        kernels = kernels.vanilla;
      };
      serverless.http-on-vsock-client = import ./serverless/http-on-vsock-client {
        inherit nixpkgs systemConfig fenix naersk;
      };
      serverless.secret-store = import ./serverless/secret-store {
        inherit nixpkgs systemConfig fenix naersk;
      };
      serverless.workerd = ./. + "/serverless/executor/runtime/workerd";
    };
  in {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
      "aarch64-linux" = nixpkgs.legacyPackages."aarch64-linux".alejandra;
    };
    packages = {
      "x86_64-linux" = rec {
        gnu = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-gnu";
          eif_arch = "x86_64";
          static = false;
        };
        musl = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-musl";
          eif_arch = "x86_64";
          static = true;
        };
        default = musl;
      };
      "aarch64-linux" = rec {
        gnu = systemBuilder {
          system = "aarch64-linux";
          rust_target = "aarch64-unknown-linux-gnu";
          eif_arch = "aarch64";
          static = false;
        };
        musl = systemBuilder {
          system = "aarch64-linux";
          rust_target = "aarch64-unknown-linux-musl";
          eif_arch = "aarch64";
          static = true;
        };
        default = musl;
      };
      "aarch64-darwin" = rec {
        gnu = systemBuilder {
          system = "aarch64-darwin";
          rust_target = "aarch64-apple-darwin";
          eif_arch = "aarch64";
          static = false;
        };
        # TODO: Figure out how to organize this properly
        musl = systemBuilder {
          system = "aarch64-darwin";
          rust_target = "aarch64-apple-darwin";
          eif_arch = "aarch64";
          static = false;
        };
        default = musl;
      };
    };
  };
}
