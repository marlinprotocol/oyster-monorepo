# Image for testing green images
{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {
    ...
  }: {
    imports = [
      # build as a green image
      (./. + "/../configs/green.nix")
    ];

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

    # root ssh for testing
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PasswordAuthentication = true;
      };
    };
    users.users.root.initialPassword = "greenroot";

    # disable firewall while testing
    networking.firewall.enable = false;
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
