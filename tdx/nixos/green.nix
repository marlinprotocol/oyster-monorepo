# goal: build as minimal an image as possible
#
# broadly, we aim to build
# - a bzImage for the kernel
# - an initrd for the initial ramdisk
# - a .raw file for the real disk
# the initrd is more or less a necessary step for bootstrapping
# since we want the real disk to be verified and/or encrypted in some fashion
#
# Green images are supposed to have
# - a known constant starting point
# - temporary writable state
# - no persistent state across reboots
#
# The broad architecture chosen for this is
# - a read only boot disk
# - dm-verity to verify the disk
# - a writable overlay on top in memory
{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {config, ...}: {
    # nixos has good presets to get started
    imports = [
      # use the minimal profile as the starting point
      "${nixpkgs}/nixos/modules/profiles/minimal.nix"
      # it will not really be interactive
      "${nixpkgs}/nixos/modules/profiles/headless.nix"
      # trim perl and anything which needs perl
      "${nixpkgs}/nixos/modules/profiles/perlless.nix"
      # build as a one-shot appliance since it will never get updated
      "${nixpkgs}/nixos/modules/profiles/image-based-appliance.nix"

      # image.repart support
      "${nixpkgs}/nixos/modules/image/repart.nix"
    ];

    # NOTE: perlless.nix also sets initrd to be systemd based
    # ensure the setup is according to that
    #
    # TODO: review if this is desirable
    # a lot of things will need to change if not

    # image version
    system.image.version = "v0.1.0";

    # state version
    system.stateVersion = "25.05";

    # forbid dependencies to ensure they truly do not get included
    # mainly to reduce image bloat
    # see perlless.nix for an example
    system.forbiddenDependenciesRegexes = [
      # technically perlless.nix should forbid perl, add it here just to be sure
      "perl"
      "python"
    ];

    # the appliance profile causes us to be locked out and nix does not like it
    # set this to tell nix we know what we are doing
    users.allowNoPasswordLogin = true;

    # FIXME: added for now just so the build works
    fileSystems = {
      "/" = {
        fsType = "tmpfs";
      };
    };

    # use image.repart to create the nixos data partition and the dm-verity hash partition
    # ref: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/image/repart-verity-store.nix#L92
    image.repart.name = "store";
    image.repart.version = "v0.1.0";
    image.repart.sectorSize = 4096;
    image.repart.partitions = {
      # hash partition
      "10-store-verity".repartConfig = {
        Type = "usr-x86-64-verity";
        Verity = "hash";
        VerityMatchKey = "store";
        Label = "store-verity";
        # Not able to auto deduce for some reason
        SizeMinBytes = "50M";
      };
      # data partition
      "20-store" = {
        storePaths = [config.system.build.toplevel];
        repartConfig = {
          Type = "usr-x86-64";
          Format = "erofs";
          Verity = "data";
          VerityMatchKey = "store";
          Label = "store";
          # Not able to auto deduce for some reason
          SizeMinBytes = "1G";
        };
      };
    };
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
  };
in {
  default = nixosSystem.config.system.build.image;
}
