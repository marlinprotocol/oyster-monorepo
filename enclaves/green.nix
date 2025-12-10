# goal: build as minimal an image as possible
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
#
# broadly, we aim to build a .raw file with
# - a GPT partition table
# - an esp partition with a unified kernel image (UKI)
# - a verity partition to hold dm-verity info
# - a data partition
{
  nixpkgs,
  systemConfig,
  attestation-server,
  keygen,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {config, ...}: {
    # nixos has good presets to get started
    imports = [
      # # use the minimal profile as the starting point
      "${nixpkgs}/nixos/modules/profiles/minimal.nix"
      # # it will not really be interactive
      # "${nixpkgs}/nixos/modules/profiles/headless.nix"
      # # trim perl and anything which needs perl
      "${nixpkgs}/nixos/modules/profiles/perlless.nix"
      # # build as a one-shot appliance since it will never get updated
      "${nixpkgs}/nixos/modules/profiles/image-based-appliance.nix"
      # build as a qemu guest so virtualization modules are included
      "${nixpkgs}/nixos/modules/profiles/qemu-guest.nix"

      # image.repart support
      "${nixpkgs}/nixos/modules/image/repart.nix"
    ];

    # NOTE: perlless.nix also sets initrd to be systemd based
    # ensure the setup is according to that

    # image id
    system.image.id = "marlin";
    # image version
    system.image.version = "v0.1.0";

    # state version
    system.stateVersion = "25.11";

    # forbid dependencies to ensure they truly do not get included
    # mainly to reduce image bloat
    # see perlless.nix for an example
    system.forbiddenDependenciesRegexes = [
      # technically perlless.nix should forbid perl, add it here just to be sure
      "perl"
      "python"
    ];

    # set a higher log level for better visibility into the boot process
    # TODO: confirm a safe level
    boot.consoleLogLevel = 7;

    # the appliance profile causes us to be locked out and nix does not like it
    # set this to tell nix we know what we are doing
    users.allowNoPasswordLogin = true;

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
    image.repart.name = "marlin";
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
        Type = "usr-x86-64-verity";
        Verity = "hash";
        VerityMatchKey = "store";
        Minimize = "best";
      };
      # data partition
      "20-store" = {
        storePaths = [config.system.build.toplevel];
        repartConfig = {
          Label = "store";
          Type = "usr-x86-64";
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

    # disable bash completions
    programs.bash.completion.enable = false;
    # disable nano
    programs.nano.enable = false;
    # disable sudo
    security.sudo.enable = false;
    # disable pam_p11 module
    security.pam.p11.enable = false;

    # extra kernel params
    # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L82
    boot.kernelParams = [
      "panic=30"
      "boot.panic_on_fail" # reboot the machine upon fatal boot issues
      "lockdown=1"
      "console=ttyS0,115200n8"
      "console=tty0"
      "random.trust_cpu=on"
      "systemd.verity=1"
      "systemd.verity_root_options=panic-on-corruption"
      "tpm_crb.force=1"
      "systemd.gpt_auto=0" # Disable systemd-gpt-auto-generator to prevent e.g. ESP mounting
    ];

    environment.systemPackages = [ 
      attestation-server
      keygen
    ];

    services.getty.autologinUser = pkgs.lib.mkOverride 10 "root";
    users.users.root.password = pkgs.lib.mkOverride 10 "nixos";

    # systemd service for testing
    systemd.services.hello = {
      description = "Hello";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeScript "loop.sh" ''
          #!${pkgs.bash}/bin/bash

          ${keygen}/bin/keygen-secp256k1 --secret /etc/ecdsa.sec --public /etc/ecdsa.pub
          echo "Hello from kmsg!. key generated" > /dev/kmsg
          cat /etc/ecdsa.pub > /dev/kmsg
        '';
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };
  };

  systemd.services.attestation = {
    description = "attestation server";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${attestation-server}/bin/oyster-attestation-server --ip-addr 0.0.0.0:1300 --pub-key /etc/ecdsa.pub > /dev/kmsg";
      Restart = "always";
      StandardError = "journal+console";
      StandardOutput = "journal+console";
    };
  };

  networking.firewall.allowedTCPPorts = [ 1300 ];

  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
  };
in {
  default = nixosSystem.config.system.build.finalImage;
  uki = nixosSystem.config.system.build.uki;
}
