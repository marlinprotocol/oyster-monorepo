{
  nixpkgs,
  systemConfig,
  fenix,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  target = systemConfig.rust_target;
  toolchain = with fenix.packages.${system};
    combine [
      stable.cargo
      stable.rustc
      targets.${target}.stable.rust-std
    ];
  naersk' = naersk.lib.${system}.override {
    cargo = toolchain;
    rustc = toolchain;
  };
  cc =
    if systemConfig.static
    then pkgs.pkgsStatic.stdenv.cc
    else pkgs.stdenv.cc;
in rec {
  uncompressed = naersk'.buildPackage {
    src = ./.;
    CARGO_BUILD_TARGET = target;
    TARGET_CC = "${cc}/bin/${cc.targetPrefix}cc";
    nativeBuildInputs = [cc];
  };

  compressed =
    pkgs.runCommand "compressed" {
      nativeBuildInputs = [pkgs.upx];
    } ''
      mkdir -p $out/bin
      cp ${uncompressed}/bin/* $out/bin/
      chmod +w $out/bin/*
      upx $out/bin/*
    '';

  docker = pkgs.dockerTools.buildImage {
    name = "marlinorg/attestation-server-custom-mock";
    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      paths = [ uncompressed ];
      pathsToLink = [ "/bin" ];
    };
    config = {
      Entrypoint = [ "/bin/oyster-attestation-server-custom-mock" ];
      Cmd = [ "--ip-addr" "0.0.0.0:1350" ];
    };
  };

  default = compressed;
}
