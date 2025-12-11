# Green images are supposed to have
# - a known constant starting point
# - temporary writable state
# - no persistent state across reboots
#
# The broad architecture chosen for this is
# - a read only boot disk
# - dm-verity to verify the disk
# - a writable overlay on top in memory
#
# broadly, we aim to build a .raw file with
# - a GPT partition table
# - an esp partition with a unified kernel image (UKI)
# - a verity partition to hold dm-verity info
# - a data partition
{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {config, modulesPath, ...}: {
    # nixos has good presets to get started
    imports = [
      # base config
      (./. + "/../configs/base.nix")
      # disk config
      (./. + "/../configs/disk-ro.nix")
    ];

    # image id
    system.image.id = "marlin-green";
    # image version
    system.image.version = "v0.1.0";

    # systemd service for testing
    systemd.services.hello = {
      description = "Hello";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = pkgs.writeScript "loop.sh" ''
          #!${pkgs.bash}/bin/bash

          while true; do
            echo "Hello from stdout!"
            echo "Hello from console!" > /dev/console
            echo "Hello from kmsg!" > /dev/kmsg
            sleep 1
          done
        '';
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
    specialArgs = {
      lib = pkgs.lib;
      modulesPath = "${nixpkgs}/nixos/modules";
      systemConfig = systemConfig;
    };
  };
in {
  default = nixosSystem.config.system.build.finalImage;
  uki = nixosSystem.config.system.build.uki;
  cmdline = nixosSystem.config.boot.kernelParams;
}
