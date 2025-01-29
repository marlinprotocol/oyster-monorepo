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
  kernels,
  compose ? ./. + "/docker-compose.yml",
  dockerImages ? [],
}: let
  system = systemConfig.system;
  nitro = nitro-util.lib.${system};
  eifArch = systemConfig.eif_arch;
  pkgs = nixpkgs.legacyPackages."${system}";
  supervisord' = "${supervisord}/bin/supervisord";
  dnsproxy' = "${dnsproxy}/bin/dnsproxy";
  keygenX25519 = "${keygen}/bin/keygen-x25519";
  itvroProxy = "${raw-proxy}/bin/ip-to-vsock-raw-outgoing";
  vtiriProxy = "${raw-proxy}/bin/vsock-to-ip-raw-incoming";
  attestationServer = "${attestation-server}/bin/oyster-attestation-server";
  keygenSecp256k1 = "${keygen}/bin/keygen-secp256k1";
  vet' = "${vet}/bin/vet";
  kernel = kernels.kernel;
  kernelConfig = kernels.kernelConfig;
  nsmKo = kernels.nsmKo;
  init = kernels.init;
  setup = ./. + "/setup.sh";
  supervisorConf = ./. + "/supervisord.conf";
  app = pkgs.runCommand "app" {} ''
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
		cp ${setup} $out/app/setup.sh
		chmod +x $out/app/*
		cp ${supervisorConf} $out/etc/supervisord.conf
		cp ${compose} $out/app/docker-compose.yml
    ${if builtins.length dockerImages == 0 
      then "# No docker images provided"
      else builtins.concatStringsSep "\n" (map (img: "cp ${img} $out/app/docker-images/") dockerImages)}
  '';
  # kinda hacky, my nix-fu is not great, figure out a better way
  initPerms = pkgs.runCommand "initPerms" {} ''
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
    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      paths = [app pkgs.busybox pkgs.nettools pkgs.iproute2 pkgs.iptables-legacy pkgs.ipset pkgs.cacert pkgs.docker];
      pathsToLink = ["/bin" "/app" "/etc"];
    };
  };
}
