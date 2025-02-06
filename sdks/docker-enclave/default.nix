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
  system = systemConfig.system;
  hostSystem = builtins.currentSystem;
  
  # Configure cross-compilation settings for Darwin
  pkgs = if builtins.match ".*darwin" hostSystem != null then
    import nixpkgs {
      system = hostSystem;
      # Properly configure cross-compilation target
      crossSystem = {
        config = "x86_64-unknown-linux-gnu";
        system = system;
        libc = "glibc";
        platform = nixpkgs.lib.systems.examples.gnu64;
      };
      # Enable cross-compilation overlays
      overlays = [
        (self: super: {
          buildPackages = super.buildPackages // {
            inherit (super) busybox nettools iproute2 iptables-legacy ipset cacert docker jq;
          };
        })
      ];
    }
  else
    nixpkgs.legacyPackages.${system};

  # Use build packages for Darwin, regular packages for Linux
  buildPkgs = if builtins.match ".*darwin" hostSystem != null then
    pkgs.buildPackages
  else
    pkgs;

  nitro = nitro-util.lib.${system};
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
  app = buildPkgs.runCommand "app" {
    inherit system;
    __structuredAttrs = true;
    preferLocalBuild = false;
    allowSubstitutes = true;
  } ''
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
    ${if builtins.length dockerImages == 0 
      then "# No docker images provided"
      else builtins.concatStringsSep "\n" (map (img: "cp ${img} $out/app/docker-images/") dockerImages)}
  '';
  initPerms = buildPkgs.runCommand "initPerms" {
    inherit system;
    __structuredAttrs = true;
    preferLocalBuild = false;
    allowSubstitutes = true;
  } ''
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
    copyToRoot = buildPkgs.buildEnv {
      name = "image-root";
      paths = [app buildPkgs.busybox buildPkgs.nettools buildPkgs.iproute2 
               buildPkgs.iptables-legacy buildPkgs.ipset buildPkgs.cacert 
               buildPkgs.docker buildPkgs.jq];
      pathsToLink = ["/bin" "/app" "/etc"];
    };
  };
}
