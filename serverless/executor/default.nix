{
  nixpkgs,
  systemConfig,
  fenix,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  target = systemConfig.rust_target;
  naersk' = naersk.lib.${system}.override {
    cargo = fenix.packages.${system}.stable.cargo;
    rustc = fenix.packages.${system}.stable.rustc;
  };
  cc =
    if systemConfig.static
    then pkgs.pkgsStatic.stdenv.cc
    else pkgs.stdenv.cc;
in rec {
  uncompressed = naersk'.buildPackage {
    src = ./.;
    CARGO_BUILD_TARGET = target;
    TARGET_CC = "${cc}/bin/cc";
    nativeBuildInputs = [
      cc
      pkgs.perl
      fenix.packages.${system}.targets.${target}.stable.rust-std
    ];
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

  default = compressed;
}
