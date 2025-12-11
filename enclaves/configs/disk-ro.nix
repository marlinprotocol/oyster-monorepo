# disk config, read only
# configure read only erofs partitions protected by dm-verity
{
  config,
  # lib,
  modulesPath,
  systemConfig,
  ...
}: {
  # nixos has good presets to get started
  imports = [
    # image.repart support
    "${modulesPath}/image/repart.nix"
  ];

  # NOTE: ideally I would like a direct overlay mount on /
  # does not work for whatever reason, go with /usr mount for now
  # it also means we might need to bind mount other paths later
  # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L19
  fileSystems = {
    "/" = {
      fsType = "tmpfs";
      options = ["mode=0755"];
    };

    "/usr" = {
      device = "/dev/mapper/usr";
      options = ["ro"];
      fsType = "erofs";
    };

    "/nix/store" = {
      device = "/usr/nix/store";
      options = ["bind"];
    };
  };

  # use image.repart to create the nixos data partition and the dm-verity hash partition
  # ref: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/image/repart-verity-store.nix#L92
  image.repart.name = "marlin-green";
  image.repart.version = "v0.1.0";
  # image.repart.sectorSize = 4096;
  image.repart.partitions = {
    # esp partition
    "00-esp".repartConfig = {
      Label = "esp";
      Type = "esp";
      Format = "vfat";
      SizeMinBytes = "128M";
      SizeMaxBytes = "128M";
    };
    # hash partition
    "10-store-verity".repartConfig = {
      Label = "store-verity";
      Type = "usr-${systemConfig.repart_arch}-verity";
      Verity = "hash";
      VerityMatchKey = "store";
      Minimize = "best";
    };
    # data partition
    "20-store" = {
      storePaths = [config.system.build.toplevel];
      repartConfig = {
        Label = "store";
        Type = "usr-${systemConfig.repart_arch}";
        Format = "erofs";
        Verity = "data";
        VerityMatchKey = "store";
        Minimize = "best";
      };
    };
  };
  # use verityStore to populate the esp partition
  image.repart.verityStore = {
    # enable it
    enable = true;
    # use a different placement path than the default of verityStore
    # TODO: check if this is needed in prod
    ukiPath = "/EFI/BOOT/BOOT${systemConfig.efi_arch}.EFI";
  };

  # extra kernel params
  # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L82
  boot.kernelParams = [
    "systemd.verity=1"
    "systemd.verity_root_options=panic-on-corruption"
    "systemd.gpt_auto=0" # Disable systemd-gpt-auto-generator to prevent e.g. ESP mounting
  ];
}
