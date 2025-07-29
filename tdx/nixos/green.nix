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
    # image.repart.sectorSize = 4096;
    image.repart.partitions = {
      # hash partition
      "10-store-verity".repartConfig = {
        Type = "usr-x86-64-verity";
        Verity = "hash";
        VerityMatchKey = "store";
        Label = "store-verity";
        Minimize = "best";
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
          Minimize = "best";
        };
      };
    };

    # disable bash completions
    programs.bash.completion.enable = false;
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
  };
in {
  default = nixosSystem.config.system.build.image;
}
#
# 4.0K	./g2gzfhkhmxf74rm60kqdhry8px8i54gk-user-generators
# 4.0K	./mvmij1c9nmdmq5si8z2pn23pay1dxi1w-system-generators
# 4.0K	./nyp36w9hii793wl6dn8yk14dccrkalw7-system-shutdown
# 8.0K	./083qz55p878d6synbhlmfaivv0y7772i-unit-systemd-pstore.service
# 8.0K	./10wi26kk0cjrifnvdsyrl8w4987z4hsb-unit-system.slice
# 8.0K	./1fa53ypqgyidqvxhdr2r3k3s0zwlfj4a-unit-initrd-switch-root.service
# 8.0K	./1jl388f71pyqbljb4g2f8j7hwqdbddhn-unit-serial-getty-hvc0.service-disabled
# 8.0K	./1kzw0nkhfrnzkmbzmvyfgfddp8vd0gsk-unit-systemd-mkswap-.service
# 8.0K	./1lcg48lg3yw873x21gybqzdmp06yqf0f-kmod-blacklist-31+20240202-2ubuntu8
# 8.0K	./1xp87acd73hahwvd10r2mqw3f1r06s29-unit-99-wireless-client-dhcp.network
# 8.0K	./27jldlfba47cyxfbawf75qhgcndxlmbv-unit-firewall.service
# 8.0K	./3cam9mp8dcm09k89hw38sb8zzb1wlazq-unit-systemd-journald-.service
# 8.0K	./3mpivh2pqa1bbyp8h3n2wk8s0fvhp2rg-unit-local-fs.target
# 8.0K	./4aiwrxc5i77s856dgx6b7yvqnxbq8x0g-unit-run-wrappers.mount
# 8.0K	./56xgl5hjb23rs5sw4dg0d9waj3zcmadi-unit-systemd-sysctl.service
# 8.0K	./5cfhznf22f85j4acy10vz0pw49p9anj0-unit-userborn.service
# 8.0K	./5vb1zklaylbilak5vkgpy563k0c1ll5g-unit-user-.service
# 8.0K	./5wap65qygkmwxnaykp2k00xbip0203ah-unit-dbus.socket
# 8.0K	./5wcg3gl5qzna3qn53id02sghbzfqa67z-unit-user-.slice
# 8.0K	./606q06nic7p6lm7sb41np4cg0ivfd957-unit-post-resume.service
# 8.0K	./662hpbnf0sl1gszl53rbqxijyxm1nmx7-unit-systemd-tmpfiles-setup.service
# 8.0K	./68ymaa7yqz8b9c3m86awp9qrs3z5gmb9-unit-keys.target
# 8.0K	./69ls0y1hb3z11kpnng191jjkhpdxdk9c-unit-multi-user.target
# 8.0K	./6i5vgirp5qi6rdd5k502iyflv1zj4lgb-unit-systemd-nspawn-.service
# 8.0K	./6ndrgnpms209lj8nl30m2vdizgkp9456-unit-systemd-resolved.service
# 8.0K	./7nqvxzxxl29wb49nl8ll3j6h4s499ilb-unit-systemd-networkd.service
# 8.0K	./7q30mi0dj7dm5zak4l5jybl53040jvg5-unit-systemd-journal-flush.service
# 8.0K	./842zkhkx2aa0zy94qws3346dnd1cm3h6-unit-remote-fs.target
# 8.0K	./87bz3pbqz5klq74xhh6s40gcg72yzy9c-unit-systemd-journald.service
# 8.0K	./88jhysfvxi6zj7g1n2s49dj5sqzyarr0-unit-user-runtime-dir-.service
# 8.0K	./8g5vq29riss8693g7syg8n0bj2d7vc9l-unit-systemd-journald-audit.socket
# 8.0K	./8zmflchf01g3wlj9j6csfnd47j0lgzcg-unit-post-resume.target
# 8.0K	./939zq7z9nvy6cvljr7nn1nypdr42sm5b-unit-systemd-oomd.service
# 8.0K	./9gkhxinv1884d1vy74rnkjd9vj2zn89p-unit-run-initramfs.mount
# 8.0K	./ac8cbfp185fggdww5azy71jniml35x6d-unit-systemd-modules-load.service
# 8.0K	./ahfbv5byr6hiqfa2jl7pi4qh35ilvxzg-fontconfig-etc
# 8.0K	./c00annkyr27i5srwbzx60r91w50yd4j6-unit-systemd-backlight-.service
# 8.0K	./c6lnj4nkq8hlbz1dpl85kmi0bwm1fw1v-unit-generate-shutdown-ramfs.service
# 8.0K	./ch4pbl0fdc26nqh6hhq3z8hqdbpv08mz-unit-nscd.service
# 8.0K	./cwps06845sikjs1p1a3y41qkkqbdzgiq-unit-systemd-remount-fs.service
# 8.0K	./djhz08ld7cqvi36v4by31mr560lbbgdy-unit-fs.target
# 8.0K	./dkd607z5qjfzmhr141zbq2rkcg4hb6hi-unit-audit.service
# 8.0K	./dp5w6pxim2mp31s3rnhd3l5lncmnw962-unit-systemd-fsck-.service
# 8.0K	./fcplhki2m26dma7vd3c435q8zd7q1ih9-unit-systemd-importd.service
# 8.0K	./fl6il46drw769y6z9h4b89yv1k55xps3-unit-nixos-fake-graphical-session.target
# 8.0K	./fq6hcdnrd6zwhly4hxn14pcmy4jx090r-etc-lowerdir
# 8.0K	./fyjydzzyj848ga8h3d3fypdkssic4za3-unit-serial-getty-ttyS0.service-disabled
# 8.0K	./g29nsjbhdlc1xzgl0a0cybqvy9mg895l-unit-systemd-networkd.socket
# 8.0K	./gv7yba2y9kkmdki9mb353fhm8dzbcds9-unit-mount-pstore.service
# 8.0K	./gyxhzj5v8k01vwva1s476ny2zll2nvzm-unit-sysinit-reactivation.target
# 8.0K	./h3hll25pfjwkbj5xvdgcisfrwp5cwbv9-unit-dbus.service
# 8.0K	./i58b1vndhiihg82iws3qkyhava4vmwdr-unit-systemd-update-utmp.service
# 8.0K	./j92c67n3pqpi8hjk2kw48f2n3fkckdah-unit-dbus.service
# 8.0K	./k3vxagv4kwy30qqf30b6nkldj1micc6f-unit-systemd-timedated.service
# 8.0K	./k6assh7n8j5h13lk2r933qahvj25q0ki-unit-container-getty-.service
# 8.0K	./kdq6sixsqcjipmqqx2pllp1mqlhfnwyg-unit-sysroot-etc.mount
# 8.0K	./ls6qdggvcbpv4d0nm3478aqdyi7aspmm-unit-systemd-udev-settle.service
# 8.0K	./lvr2n0j4vc8wf35ivx0p290d88cscfrw-unit-kmod-static-nodes.service
# 8.0K	./m2chlkrf4dhjcnq50x6qnjlfvhz9c60s-unit-network-local-commands.service-disabled
# 8.0K	./m2zsf6bnins0b904c74wyvydrpn7jv70-unit-pre-sleep.service
# 8.0K	./mdzs607j9m4h3vf913n7v4hziq90glck-unit-systemd-logind.service
# 8.0K	./mha348ryww5rm5dilq232rbamxp2srdd-unit-systemd-user-sessions.service
# 8.0K	./nckcm8izcfjb2l5x3jbgqg83dqi1q79s-unit-systemd-makefs-.service
# 8.0K	./p3lfsjk2lmigply9dn78d9i9dczzn17l-unit-prepare-kexec.service
# 8.0K	./pjm2l404alsf86kkak3ykm1f3dn3jb03-unit-suid-sgid-wrappers.service
# 8.0K	./pni0kpb8rhad26lv0ymyrpq7zdymnwqq-unit-reload-systemd-vconsole-setup.service
# 8.0K	./prx9j74pv4lz9x07pi0xk6a8lddqzr6d-unit-systemd-random-seed.service
# 8.0K	./qzv2iqy6b9jl7x76pfcplqb81gs8sarx-unit--.slice
# 8.0K	./r8rk4n72pas2xz2ia1nrjlzvxk2dgymp-unit-getty-tty1.service-disabled
# 8.0K	./rnqj7jmkfrix9478zg1lbzqznfjw66cz-unit-serial-getty-.service
# 8.0K	./s1i8611zx35k7a4x1g1zlbfh9nljdj3f-unit-save-hwclock.service
# 8.0K	./v35y0jah0ca09pn2mcr0dhbil5n5hnya-unit-getty-.service
# 8.0K	./wjc6206ak03a20h14b3szrmk47bm7zzn-unit-systemd-tmpfiles-resetup.service
# 8.0K	./wrxfizj5dnyd8w5m9m6wgw8vymskld70-unit-systemd-networkd-wait-online-.service
# 8.0K	./wwghv7lhpmjmayg450sw2zzwliirqy4j-unit-systemd-timesyncd.service
# 8.0K	./x93x42i6cjdshhwb7haflhgfb7b1bfay-unit-99-ethernet-default-dhcp.network
# 8.0K	./yc1b1n3a5z8w5zcrgfxdyj233z5jjl9q-unit-systemd-udevd.service
# 8.0K	./yyjy3ni8amh8lmpgikv6qps1ygphhg9h-unit-fstrim.timer
# 8.0K	./z5a5z6bs351awicxpr8wmis16war3s6f-unit-systemd-networkd-wait-online.service
# 8.0K	./zh9ql7xzhpj4piw8r395cfc435vpjc8i-unit-nixos-activation.service
# 12K	./03pbln3nwbxc6ars4gwskgci3wj557yy-unit-script-prepare-kexec-start
# 12K	./3wb1ngcfqajx6slx4c335lvb83js9csr-unit-script-pre-sleep-start
# 12K	./3z98iawifra8xn74bmdda6xbwgr5z0lh-unit-script-systemd-timesyncd-pre-start
# 12K	./9rbn7lvh36x8fv13qw2h6xdv6lawf39h-firewall-reload
# 12K	./ir6rlshly8xh6jhn31xa7k6hg85x4ckn-firmware
# 12K	./j2v7jjnczkj7ra7jsgq6kv3242a1l52x-getent-glibc-2.40-66
# 12K	./lqn8cpyf4nq8704p7k3wjbym51q87rh3-unit-script-post-resume-start
# 12K	./m4qaar099vcj0dgq4xdvhlbc8z4v9m22-getty
# 12K	./mmz4qa42fhacp04wfjhwlslnlfffyxjv-append-initrd-secrets
# 12K	./v9d2rq0sl3m7c8gzwq27a4wnw4hr2dvy-home-directories.conf
# 12K	./y7ljc4ir2hkwkr7lhgm9xj5hw3kw8275-firewall-stop
# 12K	./yaz54h00w6qv85lw40g0s0dw3s4s53ws-unit-script-nixos-activation-start
# 16K	./298j97sm5jr2x5z8w5q8s3mzzpb3rjjw-unit-script-suid-sgid-wrappers-start
# 16K	./7f327c4abvvas77jwh1ki5g97n08ysqp-linux-6.12.32-modules
# 16K	./7gvbikb19cl63w9lqxkqdb2cypsqwgkk-dbus-1
# 16K	./a9dhk47lhkhwary9z3acmhpaaz44cx9y-firewall-start
# 16K	./k3yib096awa7ydaf1ywf4xz0j9m1ah6z-nixos-tmpfiles.d
# 16K	./qxk9122p34qwivq20k154jflwxjjjxb3-dns-root-data-2025-04-14
# 24K	./b5qqfs0s3fslirivph8niwdxh0r0qm4g-fc-cache
# 28K	./6ijv88pwaa60gaycnvg0s4lhfxk6x1pr-move-mount-beneath-unstable-2023-11-26
# 48K	./ij3hyqgrxm93xs6rr16smky921c8zd2w-udev-rules
# 52K	./hx0kbryivbs7qccnvpmr17y6x818dhxc-libXdmcp-1.1.5
# 52K	./if83fp73ln7ksdnp1wkywvyv53b6fw3f-glibc-2.40-66-getent
# 52K	./xzfhjkn4am173n6klibs9ikvy1l08hfg-nixos-firewall-tool
# 56K	./kn1i8vpygvyr1vvhxwcy9n2m29pwixng-mkpasswd-5.6.1
# 60K	./4v64wga9rk0c919ip673j36g6ikx26ha-keyutils-1.6.3-lib
# 60K	./psjc7gv2314bxncywpvsg76gvbk2dn00-libXau-1.0.12
# 60K	./xl0gq1m1s7vb48wwlaqzirqdck0d6syb-tmpfiles.d
# 64K	./170jn0hjz46hab3376z1fj79vmn0nynm-libSM-1.2.5
# 68K	./4hjw4c56ml09jbac2mzz38qc958d3fb2-shadow-4.17.4-su
# 68K	./mhhia7plis47fhrv713fmjibqal96w1g-libaio-0.3.113
# 72K	./dqcl4f3r1z7ck24rh9dw2i6506g7wky5-which-2.23
# 76K	./9hbdbr5hikxjb16ir40w2v24gbivv22x-libmnl-1.0.5
# 80K	./j1d4jkh31x2yq5c8pibjifwcm5apa06l-fuse-3.16.2-bin
# 84K	./1l2x502h3j9bkp2ln3axm9qp70ibg7a1-qrencode-4.1.1
# 84K	./94jfyay8h0dwbakr69b91rsf8pdvah05-xauth-1.1.4
# 84K	./zhpgx7kcf8ii2awhk1lz6p565vv27jv5-attr-2.5.2-bin
# 88K	./0b1qa8fm793qvcn8bvr5kg5jl4indh9y-security-wrapper-sudoedit-x86_64-unknown-linux-musl
# 88K	./2adjiqpm8p55hfhhrw3f1kvi340allma-security-wrapper-sudo-x86_64-unknown-linux-musl
# 88K	./2q4yksm7gqgszl9axs95ylwakwk9yb8w-security-wrapper-umount-x86_64-unknown-linux-musl
# 88K	./324bqqlvdjbsixcbagdn8yjxc6zcj28a-security-wrapper-newgidmap-x86_64-unknown-linux-musl
# 88K	./7c0l3jk0fszisqidxrc2bby99dv5d261-fuse-2.9.9-bin
# 88K	./c96bpmpg46wr7pq4ls8k56jrlysmz9nr-time-1.9
# 88K	./csx6axnwacbq8ypl375p10why1fc2z8p-security-wrapper-fusermount-x86_64-unknown-linux-musl
# 88K	./m2dkj8xcpcrymd4f4p46c3m59670cj9y-security-wrapper-su-x86_64-unknown-linux-musl
# 88K	./mvgsv5643miclpcpwzv43kibj5ydpxvl-security-wrapper-newgrp-x86_64-unknown-linux-musl
# 88K	./mz9qpdl066bzg4n3rzb7x82dmx5jy386-security-wrapper-fusermount3-x86_64-unknown-linux-musl
# 88K	./p7vixy3km13dwf3g4rkg9n3qwkj2vhik-security-wrapper-sg-x86_64-unknown-linux-musl
# 88K	./rr6bdh3pdsvwjrm5wd32p2yzsz16q6z2-security-wrapper-mount-x86_64-unknown-linux-musl
# 88K	./wgq5kj4qhi78sr70mwj3bgnmx4ya87fr-security-wrapper-unix_chkpwd-x86_64-unknown-linux-musl
# 88K	./xj5y2ng1jbpx99nzi2pjajs5pdjn07rg-security-wrapper-dbus-daemon-launch-helper-x86_64-unknown-linux-musl
# 88K	./xrdkznkvi79w8pp1cyhzi40prmxilw8y-security-wrapper-newuidmap-x86_64-unknown-linux-musl
# 92K	./ci5nyvrii461hnaw267c1zvna0sjfxif-npth-1.8
# 96K	./77z9fh96318kyjmmidi558hyyssv00s8-bcache-tools-1.0.8
# 96K	./90c412b9wqhfny300rg5s2gpsbrqb31q-libffi-3.4.8
# 96K	./dfznrcrr2raj9x4bdysvs896jfnx84ih-libcbor-0.12.0
# 96K	./ygz5dcpzd7qkw44wpbd65rl6amwpxp5f-libnfnetlink-1.0.2
# 100K	./3ccwi70k69wrxq6nxy6v3iwwvawgsw6m-libressl-4.0.0-nc
# 104K	./bh1hxs692a2fv806wkiprig10j5znd7c-libcap-2.75-lib
# 108K	./1abbyfv3bpxalfjfgpmwg8jcy931bf76-bzip2-1.0.8-bin
# 108K	./675r4l9rpmaxdanw0i48z4n7gzchngv7-util-linux-minimal-2.41-login
# 108K	./zrnqzhcvlpiycqbswl0w172y4bpn0lb4-bzip2-1.0.8
# 112K	./1191qk37q1bxyj43j0y1l534jvsckyma-acl-2.3.2-bin
# 112K	./1nxchlxi7i0b1nhsyq732al8sm1blywm-util-linux-2.41-login
# 116K	./gmirqf6vp6rskn2dhfyd7haphy6kjnvk-libXext-1.3.6
# 116K	./zf61wng66ik05clni78571wfmfp5kqzq-libtasn1-4.20.0
# 120K	./dk55smr7wdjad151r7cv1pln0winqq9x-tcb-1.2
# 120K	./rmrbzp98xrk54pdlm7cxhayj4344zw6h-libassuan-3.0.2
# 128K	./2sbq4hd9imczmbb5za1awq0gvg0cbrwr-libbsd-0.12.2
# 132K	./m1arp7n5z5cqsv88l0gjazzfvkc8ia84-fontconfig-conf
# 136K	./jp25r6a51rfhnapv9lp8p00f2nzmfxxz-bind-9.20.9-host
# 140K	./qqpgwzhpakcqaz6fiy95x19iydj471ca-pcsclite-2.3.0-lib
# 144K	./bkm4ppw3rpyndsvy5r18fjpngg2730ip-libICE-1.1.2
# 148K	./89bxhx3rhk6r4d5fvwaysrykpmvmgcnm-kmod-31-lib
# 148K	./bxs5j3zhh35nwhyhwc3db724c7nzfl36-libpsl-0.21.5
# 148K	./drqk69j2bclr0d5f4sppx9g6arplc3vf-user-units
# 152K	./jws80m7djgv03chq0ylw7vmv3vqsbvgg-util-linux-minimal-2.41-swap
# 152K	./zma6jllb9xn22i98jy9n8mz3wld9njwk-util-linux-2.41-swap
# 156K	./agpxymqp96k4bksyz3bbzr5y8jgykf4p-util-linux-minimal-2.41-mount
# 156K	./g51ca42mmgxzz7xngf0jzhwd4whi19lj-util-linux-2.41-mount
# 160K	./qizipyz9y17nr4w4gmxvwd3x4k0bp2rh-libxcrypt-4.4.38
# 160K	./srby6wmvg7dp454pwb6qvaxdiri38sc1-zlib-1.3.1
# 172K	./2bjcjfzxnwk3zjhkrxi3m762p8dv6f1s-libcap-ng-0.8.5
# 184K	./2x51wvk10m9l014lyrfdskc3b360ifjp-ed-1.21.1
# 192K	./afhkqb5a94zlwjxigsnwsfwkf38h21dk-gzip-1.14
# 196K	./hlmmf01lhg62fpqhzispzs8rhzn7gg4p-libXmu-1.2.1
# 200K	./idgpi0g62yyq8plhrdc2ps2gcrkd44jz-dash-0.5.12
# 212K	./6hqzbvz50bm87hcj4qfn51gh7arxj8a6-gcc-14.2.1.20250322-libgcc
# 212K	./a7zbljj0cwkbfzn22v6s2cbh39dj9hip-libseccomp-2.6.0-lib
# 212K	./za53jjhjl1xajv3y1zpjvr9mh4w0c1ay-xgcc-14.2.1.20250322-libgcc
# 228K	./8syylmkvnn7lg2nar9fddpp5izb4gh56-attr-2.5.2
# 232K	./sm4b1vl7578rl2yiss62acs7ls7qinad-lvm2-2.03.31
# 236K	./v7rzgm8p6p0ghg5mqcin4vbx6pcrvc0j-nghttp2-1.65.0-lib
# 240K	./3mi59bgj22xx29dyss7jhmx3sgznd85m-acl-2.3.2
# 240K	./s2np0ri22gq9pq0fnv3yqjsbsbmw16xi-curl-8.13.0-bin
# 260K	./x0kaspzb5jqvgp357bj27z6iq24ximfg-patch-2.7.6
# 264K	./64zabz1hxymxbcvp78hp9kacrygnf9l9-fontconfig-2.16.0-bin
# 264K	./677sx4qrmnmgk83ynn0sw8hqgh439g6b-json-c-0.18
# 264K	./qksnsi17k7sszn90s6vsgj01kmnaldaj-nixos-system-nixos-25.05.20250609.3ae15af
# 268K	./6wrjb93m2arv7adx6k2x9nlb0y7rmgpi-libnetfilter_conntrack-1.1.0
# 276K	./1dxfw2zshri809ddyfqllvff3cfj96ma-libmicrohttpd-1.0.1
# 276K	./98zamhd8d0jq3skqwz28dlgph94mrqir-xz-5.8.1-bin
# 280K	./51sr6m5fb8fff9vydnz7gkqyl5sjpixl-lz4-1.10.0-lib
# 280K	./xs1qm9vidbfn1932z9csmnwdkrx4lch6-libedit-20240808-3.1
# 284K	./4f7ssdb8qgaajl4pr1s1p77r51qsrb8y-kexec-tools-2.0.29
# 284K	./9mcjnb75xq17mvr8ikm3sg5yhx6ga62r-libuv-1.50.0
# 300K	./qvyvscqgr6vyqvmjdgxqa521myv5db0p-kmod-31
# 300K	./y3x4m9wy3a731ibvgvs194j10znc392m-libpng-apng-1.6.46
# 308K	./nmyh57dqf1v6l6swghywkrb63aqmzzh8-fuse-3.16.2
# 320K	./j0bzxly2rvcym1zkhn393adiqcwn8np6-expat-2.7.1
# 324K	./66ld17ifbjz63firjjv88aydxsc3rcs6-less-668
# 332K	./nfwlyasnxxdbnpiziw2nixwkz9b5f7g3-publicsuffix-list-0-unstable-2025-03-12
# 352K	./9642gi5dl4w9nkhab0l6xry685cg403c-libssh2-1.11.1
# 372K	./f7y5q4jwja2z3i5zlylgbv5av6839a54-libnftnl-1.2.9
# 388K	./l9xn7mbn0wh0z7swfcfj1n56byvcrisw-zstd-1.5.7-bin
# 420K	./mzvz45f54a0r0zjjygvlzn6pidfkkwj3-audit-4.0.3-lib
# 440K	./1warn5bb3r7jwfkpdgr4npab3s63sivj-liburcu-0.15.2
# 448K	./2pvhq9kgqh5669qj6805vpasngivad8h-lvm2-2.03.31-lib
# 456K	./ldn53xpxivf489d7z673c95fkihs5l8r-fontconfig-2.16.0-lib
# 460K	./l7rjijvn6vx8njaf95vviw5krn3i9nnx-nss-cacert-3.111-p11kit
# 476K	./56fi3kcbg9haxf5c1innrn2p9dx2da2j-libmd-1.1.0
# 496K	./yi0knhi2qccafj49a8yd76rizllzx7bd-dbus-1.14.10-lib
# 500K	./971mpk4nqhqcxggx0yi60w9y1ya570bj-readline-8.2p13
# 508K	./2rxzdljx3dp4cgj1xlald496gdsjnwj8-libXt-1.3.1
# 524K	./iwgzrp73d34lc2m3gdfhbqpwvcx2q4hw-etc
# 548K	./gvbvgjjbg1wvni45vzza0mgwsyvkvb0g-userborn-0.4.0
# 576K	./j4gc8fk7wazgn2hqnh0m8b12xx6m1n75-iana-etc-20250108
# 584K	./pyfpxwjw1a7fj5j7n2czlk4g7lvzhvhy-dosfstools-4.2
# 624K	./skd9hg5cdz7jwpq1wp38fvzab9y8p0m6-net-tools-2.10
# 628K	./4qks83jh0avrs4111c6rlwn3llqlily0-ldns-1.8.4
# 636K	./6nkqdqzpa75514lhglgnjs5k4dklw4sb-libidn2-2.3.8
# 672K	./rys6134aqazihxi4g5ayc0ky829v7mf0-dbus-1.14.10
# 704K	./p3sknfsxw0rjmxbbncal6830ic9bbaxv-audit-4.0.3-bin
# 740K	./m4yrdwg3zv50mw8hy2zni5dyy7ljlg7j-nettle-3.10.1
# 744K	./6fv8ayzjvgyl3rdhxp924zdhwvhz2iq6-nss-cacert-3.111
# 760K	./1rlljm73ch98b2q9qqk8g0vhv2n9mya8-libapparmor-4.1.0
# 760K	./zh5iazbs69x4irfdml5fzbh9nm05spgb-dejavu-fonts-minimal-2.37
# 780K	./9hpylx077slqmzb5pz8818mxjws3appp-iputils-20240905
# 808K	./kxhsmlrscry4pvbpwkbbbxsksmzg0gp0-gmp-with-cxx-6.3.0
# 808K	./nzg6zqsijbv7yc95wlfcdswx6bg69srq-gmp-with-cxx-6.3.0
# 916K	./yai7mpy5d4rw0jvflyxdf0vzjkiqxhv6-libevent-2.1.12
# 932K	./bmmmy3sz3fmlxx64rlw1apm7ffywpyap-libpwquality-1.4.5-lib
# 944K	./g91dviqva4rkkw8lw30zy3gj14c1p23s-libarchive-3.7.8-lib
# 976K	./7a8gf62bfl22k4gy2cd300h7cvqmn9yl-brotli-1.1.0-lib
# 1004K	./v578vkzh0qhzczjvrzf64lqb2c74d5pk-curl-8.13.0
# 1.1M	./5f0bv68v1sjrp4pnr8c6p7k04271659w-libfido2-1.15.0
# 1.1M	./9z7wv6k9i38k83xpbgqcapaxhdkbaqhz-libgpg-error-1.51
# 1.1M	./clbb2cvigynr235ab5zgi18dyavznlk2-gnused-4.9
# 1.1M	./pa60s415p92gnhv5ffz1bmfgzzfvhvd8-xz-5.8.1
# 1.1M	./zfb1cj0swnadhvfjvp0jm2zhgwiy927f-make-initrd-ng-0.1.0
# 1.2M	./8y5hcryppj548yfx6akiw93qrw8zv6js-unbound-1.23.0-lib
# 1.2M	./bmckdjhp1cn78n4md1m55zglpqxwijj3-libtpms-0.10.0
# 1.2M	./d8vq999dg607ha6718fimpakacfax0gd-zstd-1.5.7
# 1.2M	./md8kapandyhs7bbw5s782aanw38p2kax-gnupg-2.4.7
# 1.4M	./6czlz4s2n2lsvn6xqlfw59swc0z21n89-nsncd-1.5.1
# 1.4M	./gqmr3gixlddz3667ba1iyqck3c0dkpvd-gnugrep-3.11
# 1.4M	./sjsapivqvz7hs93rbh1blcd7p91yvzk1-console-env
# 1.5M	./0dqmgjr0jsc2s75sbgdvkk7d08zx5g61-libgcrypt-1.10.3-lib
# 1.5M	./1r4qwdkxwc1r3n0bij0sq9q4nvfraw6i-libpcap-1.10.5
# 1.5M	./6ycmjimp1h3z4xgf47jjxxmps9skbdw1-cpio-2.15
# 1.5M	./izcym87m13m4nhjbxr2b2fp0r6wpl1s6-fontconfig-2.16.0
# 1.5M	./wh2bg504p87d6120126dml36pcqkldic-system-units
# 1.6M	./xv0pc5nc41v5vi0lac1i2d353s3rqlkm-libxml2-2.13.8
# 1.7M	./635dz3p1afjwym9snp2r9hm0vaznwngy-libnl-3.11.0
# 1.7M	./xy4jjgw87sbgwylm5kn047d9gkbhsr9x-bash-5.2p37
# 1.7M	./yfjzkkkyxcalyj7l1n4d4y6s81i65hmy-sqlite-3.48.0
# 1.8M	./qn01pv62sbpzbsy0a6m0q23syrmkk3bv-libxcb-1.17.0
# 1.9M	./87fck6hm17chxjq7badb11mq036zbyv9-coreutils-9.7
# 1.9M	./a9c6rz5183psp30q1nhkakis6ab4km4b-pcre2-10.44
# 1.9M	./lcgn80w8gn12cisvk77zavzgzkkyn62l-initrd-bin-env
# 2.0M	./7f3nwfvk0f32663rz1xn38cbsl66idx2-libbpf-1.5.0
# 2.0M	./7h0sard22wnbz0jyz07w8y9y0fcs795r-diffutils-3.12
# 2.0M	./gmydihdyaskbwkqwkn5w8yjh9nzjz56p-udev-path
# 2.0M	./v03zr9slrp64psxlpwh7gn0m5gcdglwm-systemd-minimal-libs-257.5
# 2.0M	./x2wlg9cm3yrinz290r4v2fxpbpkw8gki-libcap-2.75
# 2.0M	./yypqcvqhnv8y4zpicgxdigp3giq81gzb-libunistring-1.3
# 2.1M	./5i64l61if26whc3r9lzq6ycxpd2xnlgm-freetype-2.13.3
# 2.1M	./r03ly1w54924k8fag1dhjl3yrllj6czd-util-linux-minimal-2.41-lib
# 2.2M	./1fzwkn364racyk53ylhbzjd729ql8x8b-linux-6.12.32-modules-shrunk
# 2.2M	./7y59hzi3svdj1xjddjn2k7km96pifcyl-findutils-4.10.0
# 2.7M	./m4w8d2h3v76anng7s9cv9c1iq9w6y2jj-cryptsetup-2.7.5
# 2.8M	./303islqk386z1w2g1ngvxnkl4glfpgrs-glibc-2.40-66-bin
# 3.0M	./0ip389clsbrbjmhmrysgfghqnhx8qlfd-glibc-locales-2.40-66
# 3.0M	./bmjb20jhxkq881f43pd264240sp677an-krb5-1.21.3-lib
# 3.1M	./2vd9h77mrciiff8ldj1260qd6dlylpvh-nano-8.4
# 3.1M	./vrdwlbzr74ibnzcli2yl1nxg9jqmr237-linux-pam-1.6.1
# 3.1M	./wrxvqj822kz8746608lgns7h8mkpn79f-gnutar-1.35
# 3.1M	./wxkbp7kwvpxvjh28rigmf6lfq64zlsyj-iptables-1.8.11
# 3.2M	./dh54wizfsivqa4ygx76jn49lpxkqbaf6-lvm2-2.03.31-bin
# 3.2M	./x3bxjpkcbfyzmy5695g1cchf04fbz8ca-procps-4.0.4
# 3.3M	./fcyn0dqszgfysiasdmkv1jh3syncajay-gawk-5.3.2
# 3.3M	./kvycshxci0x434bcgnsvr9c0qgmsw6v5-libressl-4.0.0
# 3.3M	./mpvxc1dbpnk74345lk69dw497iqcjvj0-libX11-1.8.12
# 3.3M	./qyihkwbhd70ynz380whj3bsxk1d2lyc4-tzdata-2025b
# 3.4M	./y4ygj0jgwmz5y8n7jg4cxgxv4lc1pwfy-jemalloc-5.3.0
# 3.5M	./yba197xwc8vvxv9wmcrs9bngmmgp5njb-gnutls-3.8.9
# 3.6M	./fm2ky0fkkkici6zpf2s41c1lvkcpfbm5-db-4.8.30
# 3.8M	./a885zzx9s5y8dxbfvahwdcwcx6pdzm9q-tpm2-tss-4.1.3
# 4.0M	./6mnmfhfsz94zgsyskz7zanian98ssykf-bind-9.20.9-lib
# 4.1M	./cly4pxh7avd579girjmpxmx8z6ad4dyp-elfutils-0.192
# 4.3M	./10glq3a1jbsxv50yvcw1kxxz06vq856w-db-5.3.28
# 4.4M	./9r81a64smasyz3j7x3ah684hyzivmplx-kbd-2.7.1
# 4.4M	./gsman0cwlms2l679bla5vgmf21jc5lvl-systemd
# 4.6M	./bxznmkg59a4s2p559fmbizc2qcgjr3ny-iproute2-6.14.0
# 4.6M	./qm7ybllh3nrg3sfllh7n2f6llrwbal58-bash-completion-2.16.0
# 5.2M	./b895xnbwyfj1msj6ljcsvwfdhwqhd2vd-shadow-4.17.4
# 5.7M	./9m6a4iv2nh6v4aga830r499s4arknsfb-p11-kit-0.25.5
# 6.7M	./bajihimwaaswi7m2aad4ypx34gxm62k7-system-path
# 6.7M	./ywy0hjiydvv561a5wds6ba7z059zj9im-sudo-1.9.16p2
# 7.4M	./1q9lw4r2mbap8rsr8cja46nap6wvrw2p-bash-interactive-5.2p37
# 7.9M	./8pviily4fgsl02ijm65binz236717wfs-openssl-3.4.1
# 8.4M	./mw6bvyrwv9mk36knn65r80zp8clnw9jl-util-linux-minimal-2.41-bin
# 8.7M	./gvmv77v5b0dnqfdwg2jdajyz42r021r5-openssh-10.0p2
# 9.1M	./x4a9ksmwqbhirjxn82cddvnhqlxfgw8l-linux-headers-static-6.12.7
# 9.3M	./af291yai47szhz3miviwslzrjqky31xw-util-linux-2.41-bin
# 9.7M	./7c0v0kbrrdc2cqgisi78jdqxn73n3401-gcc-14.2.1.20250322-lib
# 10M	./a7h3ly9qzh8wk1vsycpdk69xp82dl5ry-cracklib-2.10.0
# 11M	./rrnlyc5y7gd5b0f91a89vbw1flhnlm73-file-5.46
# 13M	./5c38fjjwfnlfjiiq62qyrr545q0n60ki-util-linux-2.41-lib
# 13M	./vfmnmqsnfiiqmphy7ffh2zqynsxfck1q-ncurses-6.5
# 14M	./axi2kqwlrr7lvkfj42p7mav2x7apffrq-coreutils-full-9.7
# 19M	./ykzprjkb2l61gnlcm368vh8wnj7adwx6-systemd-minimal-257.5
# 22M	./v4bvd04y48b0y2yf0v4kc37wzvgak08h-initrd-linux-6.12.32
# 31M	./cg9s562sa33k78m63njfn1rw47dp9z0i-glibc-2.40-66
# 43M	./if9z6wmzmb07j63c02mvfkhn1mw1w5p4-systemd-257.5
# 165M	./h3w4lxpqlgsimj93ajlzakqdxa5khap3-linux-6.12.32
# 610M	.

