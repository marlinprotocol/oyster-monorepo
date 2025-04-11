{
  nixpkgs,
  systemConfig,
  supervisord,
  keygen, 
  attestation-server-mock, 
  derive-server-mock,
  compose ? ./. + builtins.getEnv "COMPOSE",
  dockerImages ? let
    envValue = builtins.getEnv "DOCKER_IMAGES";
  in if envValue == "" then [ ] else builtins.fromJSON (envValue),
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";

  baseImage = if system == "x86_64-linux" then
    pkgs.dockerTools.pullImage {
      imageName = "alpine";
      sha256 = "sha256-FaT/+7fpq7h7mdRq2mNbJToI2iEbqpMjIrAYpk9rMds=";
      imageDigest = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c";
    }
  else if system == "aarch64-linux" || system == "aarch64-darwin" then
    pkgs.dockerTools.pullImage {
      imageName = "arm64v8/alpine";
      sha256 = "sha256-Lm8O2kraSOOVxKMuVKxU7oOGfLMUsnsykoy50HgyqGw=";
      imageDigest = "sha256:757d680068d77be46fd1ea20fb21db16f150468c5e7079a08a2e4705aec096ac";
    }
  else
    throw "Unsupported architecture: ${system}";       

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
    ${
      if compose == ./.
      then "# No docker compose specified"
      else "cp ${compose} $out/app/docker-compose.yml"
    }  
    ${
      if builtins.length dockerImages == 0
      then "# No docker images provided"
      else builtins.concatStringsSep "\n" (map (img: "cp ${./. + img} $out/app/docker-images/") dockerImages)
    }
  '';  

in {
  default = pkgs.dockerTools.buildImage {
    name = "marlinorg/local-dev-image";
    tag = "latest";

    fromImage = baseImage;

    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      paths = [ app pkgs.docker ];
      pathsToLink = ["/bin" "/app" "/etc" ];
    };

    config = {
      WorkingDir = "/app";
      Cmd = ["/app/setup.sh"];
    };
  };
}
