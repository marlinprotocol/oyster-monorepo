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
  lib,
  ...
}: {
  imports = [
    # base config
    (./. + "/base.nix")
    # disk config
    (./. + "/disk-ro.nix")
    # dns config
    (./. + "/dns.nix")
  ];

  # image id
  system.image.id = lib.mkDefault "marlin-green";
  # image version
  system.image.version = lib.mkDefault "v0.1.0";
}
