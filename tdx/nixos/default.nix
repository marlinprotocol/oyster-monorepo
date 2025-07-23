{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
in {
  # goal: build as minimal a config as possible
  #
  # broadly, we aim to build
  # - a bzImage for the kernel
  # - an initrd for the initial ramdisk
  # - a .raw file for the real disk
  # the initrd is more or less a necessary step for bootstrapping
  # since we want the real disk to be verified and/or encrypted in some fashion

  # nixos has good presets to get started
  imports = [
    # use the minimal profile as the starting point
    "${nixpkgs}/nixos/modules/profiles/minimal.nix"
    # it will not really be interactive
    "${nixpkgs}/nixos/modules/profiles/headless.nix"
    # trim perl and anything which needs perl
    "${nixpkgs}/nixos/modules/profiles/perlless.nix"
  ];

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
}
