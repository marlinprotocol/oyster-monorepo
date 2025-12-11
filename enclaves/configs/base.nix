# base config
# build as minimal an image as possible
{
  # lib,
  modulesPath,
  ...
}: {
  # nixos has good presets to get started
  imports = [
    # use the minimal profile as the starting point
    "${modulesPath}/profiles/minimal.nix"
    # it will not really be interactive
    "${modulesPath}/profiles/headless.nix"
    # trim perl and anything which needs perl
    "${modulesPath}/profiles/perlless.nix"
    # build as a one-shot appliance since it will never get updated
    "${modulesPath}/profiles/image-based-appliance.nix"
    # build as a qemu guest so virtualization modules are included
    "${modulesPath}/profiles/qemu-guest.nix"
  ];
  
  # NOTE: perlless.nix also sets initrd to be systemd based
  # ensure the setup is according to that

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
    # panic=X option already set by headless.nix
    # boot.panic_on_fail option already set by headless.nix
    "lockdown=1"
    "console=ttyS0,115200n8"
    "console=tty0"
    "random.trust_cpu=on"
    "tpm_crb.force=1"
  ];
}
