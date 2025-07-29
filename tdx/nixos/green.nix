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
  config = {
    # nixos has good presets to get started
    imports = [
      # use the minimal profile as the starting point
      "${nixpkgs}/nixos/modules/profiles/minimal.nix"
      # it will not really be interactive
      "${nixpkgs}/nixos/modules/profiles/headless.nix"
      # trim perl and anything which needs perl
      "${nixpkgs}/nixos/modules/profiles/perlless.nix"
    ];

    # NOTE: perlless.nix also sets initrd to be systemd based
    # ensure the setup is according to that
    #
    # TODO: review if this is desirable
    # a lot of things will need to change if not

    # image version
    system.image.version = "v0.1.0";

    # forbid dependencies to ensure they truly do not get included
    # mainly to reduce image bloat
    # see perlless.nix for an example
    system.forbiddenDependenciesRegexes = [
      # technically perlless.nix should forbid perl, add it here just to be sure
      "perl"
      "python"
    ];

    # nix itself is not needed once the image is built
    nix.enable = false;

    # FIXME: added for now just so the build works
    fileSystems = {
      "/" = {
        fsType = "tmpfs";
      };
    };
  };
  nixos = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [config];
  };
in {
  default = nixos.config.system.build.toplevel;
}
