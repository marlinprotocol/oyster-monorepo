{
  nixpkgs,
  systemConfig,
  supervisord,
  keygen, 
  attestation-server-mock, 
  derive-server-mock,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";

  supervisord' = "${supervisord}/bin/supervisord";
  keygenX25519 = "${keygen}/bin/keygen-x25519";
  attestationServerMock = "${attestation-server-mock}/bin/oyster-attestation-server-mock";
  keygenSecp256k1 = "${keygen}/bin/keygen-secp256k1";
  deriveServerMock = "${derive-server-mock}/bin/kms-derive-server-mock";
  setup = ./. + "/setup.sh";
  supervisorConf = ./. + "/supervisord.conf";

  app = pkgs.runCommand "app" {} ''
    echo Preparing the app folder
    pwd
    mkdir -p $out
    mkdir -p $out/app
    mkdir -p $out/etc
    mkdir -p $out/tmp
    mkdir -p $out/app/docker-images
    touch $out/app/init-params-digest
    cp ${supervisord'} $out/app/supervisord
    cp ${keygenX25519} $out/app/keygen-x25519
    cp ${attestationServerMock} $out/app/attestation-server
    cp ${keygenSecp256k1} $out/app/keygen-secp256k1
    cp ${deriveServerMock} $out/app/kms-derive-server
    cp ${setup} $out/app/setup.sh
    chmod +x $out/app/*
    cp ${supervisorConf} $out/etc/supervisord.conf
  '';  

in {
  default = pkgs.dockerTools.buildImage {
    name = "marlinorg/local-dev-image";

    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      paths = [ app pkgs.docker pkgs.busybox pkgs.cacert ];
      pathsToLink = ["/bin" "/app" "/etc" "/tmp" ];
    };

    config = {
      WorkingDir = "/app";
      Cmd = ["/app/setup.sh"];
    };
  };
}