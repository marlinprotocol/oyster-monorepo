{
  nixpkgs,
  systemConfig,
  nitro-util,
  supervisord,
  dnsproxy,
  keygen,
  tcp-proxy,
  attestation-server,
  executor,
  kernels,
  workerd,
}: let
  system = systemConfig.system;
  nitro = nitro-util.lib.${system};
  eifArch = systemConfig.eif_arch;
  pkgs = nixpkgs.legacyPackages."${system}";
  supervisord' = "${supervisord}/bin/supervisord";
  dnsproxy' = "${dnsproxy}/bin/dnsproxy";
  itvtProxy = "${tcp-proxy}/bin/ip-to-vsock-transparent";
  vtiProxy = "${tcp-proxy}/bin/vsock-to-ip";
  attestationServer = "${attestation-server}/bin/oyster-attestation-server";
  keygenSecp256k1 = "${keygen}/bin/keygen-secp256k1";
  executor' = "${executor}/bin/oyster-serverless-executor";
  kernel = kernels.kernel;
  kernelConfig = kernels.kernelConfig;
  nsmKo = kernels.nsmKo;
  init = kernels.init;
  setup = ./. + "/setup.sh";
  supervisorConf = ./. + "/supervisord.conf";
  cgroupSetup = ./. + "/cgroupv2_setup.sh";
  execConf = ./. + "/oyster_serverless_executor_config.json";
  app = pkgs.runCommand "app" {nativeBuildInputs = [pkgs.gcc];} ''
    echo Preparing the app folder
    pwd
    mkdir -p $out
    mkdir -p $out/app
    mkdir -p $out/etc
    cp ${supervisord'} $out/app/supervisord
    cp ${itvtProxy} $out/app/ip-to-vsock-transparent
    cp ${vtiProxy} $out/app/vsock-to-ip
    cp ${attestationServer} $out/app/attestation-server
    cp ${dnsproxy'} $out/app/dnsproxy
    cp ${keygenSecp256k1} $out/app/keygen-secp256k1
    cp ${executor'} $out/app/oyster-serverless-executor
    cp ${setup} $out/app/setup.sh
    cp ${cgroupSetup} $out/app/cgroupv2_setup.sh
    cp ${workerd} $out/app/workerd
    chmod +x $out/app/*
    chmod +w $out/app/workerd
    patchelf --set-interpreter "$(cat $NIX_CC/nix-support/dynamic-linker)" $out/app/workerd
    cp ${supervisorConf} $out/etc/supervisord.conf
    cp ${execConf} $out/etc/oyster_serverless_executor_config.json
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
      paths = [app pkgs.busybox pkgs.nettools pkgs.iproute2 pkgs.iptables-legacy pkgs.cacert pkgs.libcgroup];
      pathsToLink = ["/bin" "/app" "/etc"];
    };
  };
}
