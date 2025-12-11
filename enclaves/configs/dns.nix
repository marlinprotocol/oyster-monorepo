# dns config
# set up systemd-resolved with DoT
{
  ...
}: {
  # set up systemd-resolved
  services.resolved = {
    # enable systemd-resolved
    enable = true;
    # enable for all domains
    domains = [ "~." ];
    # disable fallbacks to prevent bypass
    fallbackDns = [];
    # enable DoT to prevent MITM
    dnsovertls = "true";
  };
  # set up nameservers
  networking.nameservers = [
    # Quad9
    "9.9.9.9"
    # Cloudflare
    "1.1.1.1"
    "1.0.0.1"
    # Google
    "8.8.8.8"
    "8.8.4.4"
  ];
}
