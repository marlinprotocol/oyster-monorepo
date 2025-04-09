{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  src = ./.;
in rec {
  uncompressed = pkgs.stdenv.mkDerivation {
    pname = "uncompressed";
    version = "0.1.0";

    src = src;

    nativeBuildInputs = [pkgs.clang pkgs.linuxHeaders pkgs.libbpf pkgs.bpftools];

    buildPhase = ''
      # blergh
      ${pkgs.clang.cc}/bin/clang -v -O3 -g -Wall -target bpf -c intercept.bpf.c -o intercept.bpf.o -I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include
      bpftool gen skeleton intercept.bpf.o > intercept.skel.h
      clang -v -O3 forward.c -o proxy -lbpf
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp proxy $out/bin/proxy
      chmod +x $out/bin/proxy
    '';
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
