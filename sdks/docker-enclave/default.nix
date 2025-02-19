{
  nixpkgs,
  systemConfig,
  nitro-util,
  supervisord,
  dnsproxy,
  keygen,
  raw-proxy,
  attestation-server,
  vet,
  derive-server,
  init-params-manager,
  kernels,
  compose ? ./. + "/docker-compose.yml",
  dockerImages ? [],
}: let
  # Define the build platform (macOS) and target platform (Linux)
  buildSystem = builtins.currentSystem;  # This will be x86_64-darwin or aarch64-darwin
  targetSystem = systemConfig.system;     # This should be x86_64-linux
  
  # Setup cross-compilation
  pkgs = import nixpkgs {
    system = buildSystem;
    crossSystem = {
      config = "x86_64-unknown-linux-gnu";
      system = targetSystem;
    };
  };

  # Use cross-compiled packages
  crossPkgs = pkgs.pkgsCross.${targetSystem};
  
  # Rest of the existing configuration using crossPkgs instead of pkgs
  nitro = nitro-util.lib.${targetSystem};
  eifArch = systemConfig.eif_arch;
  supervisord' = "${supervisord}/bin/supervisord";
  dnsproxy' = "${dnsproxy}/bin/dnsproxy";
  keygenX25519 = "${keygen}/bin/keygen-x25519";
  itvroProxy = "${raw-proxy}/bin/ip-to-vsock-raw-outgoing";
  vtiriProxy = "${raw-proxy}/bin/vsock-to-ip-raw-incoming";
  attestationServer = "${attestation-server}/bin/oyster-attestation-server";
  keygenSecp256k1 = "${keygen}/bin/keygen-secp256k1";
  deriveServer = "${derive-server}/bin/kms-derive-server";
  initParamsDecoder = "${init-params-manager}/bin/init-params-decoder";
  vet' = "${vet}/bin/vet";
  kernel = kernels.kernel;
  kernelConfig = kernels.kernelConfig;
  nsmKo = kernels.nsmKo;
  init = kernels.init;
  setup = ./. + "/setup.sh";
  supervisorConf = ./. + "/supervisord.conf";
  app = crossPkgs.runCommand "app" {} ''
    echo Preparing the app folder
    pwd
    mkdir -p $out
    mkdir -p $out/app
    mkdir -p $out/etc
    mkdir -p $out/app/docker-images
    cp ${supervisord'} $out/app/supervisord
    cp ${keygenX25519} $out/app/keygen-x25519
    cp ${itvroProxy} $out/app/ip-to-vsock-raw-outgoing
    cp ${vtiriProxy} $out/app/vsock-to-ip-raw-incoming
    cp ${attestationServer} $out/app/attestation-server
    cp ${dnsproxy'} $out/app/dnsproxy
    cp ${vet'} $out/app/vet
    cp ${keygenSecp256k1} $out/app/keygen-secp256k1
    cp ${deriveServer} $out/app/kms-derive-server
    cp ${initParamsDecoder} $out/app/init-params-decoder
    cp ${setup} $out/app/setup.sh
    chmod +x $out/app/*
    cp ${supervisorConf} $out/etc/supervisord.conf
    cp ${compose} $out/app/docker-compose.yml
    ${
      if builtins.length dockerImages == 0
      then "# No docker images provided"
      else builtins.concatStringsSep "\n" (map (img: "cp ${img} $out/app/docker-images/") dockerImages)
    }
  '';
  # kinda hacky, my nix-fu is not great, figure out a better way
  initPerms = crossPkgs.runCommand "initPerms" {} ''
    cp ${init} $out
    chmod +x $out
  '';
in {
  default = nitro.buildEif {
    name = "enclave";
    arch = eifArch;

    init = initPerms;
    kernel = kernel;
    kernelConfig = kernelConfig;
    nsmKo = nsmKo;
    cmdline = builtins.readFile nitro.blobs.${eifArch}.cmdLine;

    entrypoint = "/app/setup.sh";
    env = "";
    copyToRoot = crossPkgs.buildEnv {
      name = "image-root";
      paths = [
        app 
        crossPkgs.busybox 
        crossPkgs.nettools 
        crossPkgs.iproute2 
        crossPkgs.iptables-legacy 
        crossPkgs.ipset 
        crossPkgs.cacert 
        crossPkgs.docker 
        crossPkgs.jq
      ];
      pathsToLink = ["/bin" "/app" "/etc"];
    };
  };
}
