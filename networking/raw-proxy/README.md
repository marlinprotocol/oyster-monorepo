![Marlin Oyster Logo](./logo.svg)

# Raw Proxies

This repository contains raw IP proxies used to tunnel IP traffic through a vsock interface. They are primarily used in the tuna family of images. This repository contains the following proxies:
- ip-to-vsock-raw-incoming
- ip-to-vsock-raw-outgoing
- vsock-to-ip-raw-incoming
- vsock-to-ip-raw-outgoing

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.networking.raw-proxy.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## ip-to-vsock-raw-incoming

The ip-to-vsock-raw-incoming proxy listens on a netfilter queue for raw packets and proxies them to a fixed vsock address. Meant to be used in conjunction with [vsock-to-ip-raw-incoming](#vsock-to-ip-raw-incoming) proxy and iptables rules to intercept packets and redirect them into a netfilter queue.

### Usage

```bash
$ ./target/release/ip-to-vsock-raw-incoming --help
Usage: ip-to-vsock-raw-incoming --vsock-addr <VSOCK_ADDR> --queue-num <QUEUE_NUM>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address to forward packets to <cid:port>
  -q, --queue-num <QUEUE_NUM>    nfqueue number of the listener <num>
  -h, --help                     Print help
  -V, --version                  Print version
```

## vsock-to-ip-raw-incoming

The vsock-to-ip-raw-incoming proxy listens on a vsock address for raw packets and proxies them to a fixed network device. Meant to be used in conjunction with [ip-to-vsock-raw-incoming](#ip-to-vsock-raw-incoming) proxy to receive raw packets.

### Usage

```bash
$ ./target/release/vsock-to-ip-raw-incoming --help
Usage: vsock-to-ip-raw-incoming --vsock-addr <VSOCK_ADDR> --device <DEVICE>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address to listen on <cid:port>
  -d, --device <DEVICE>          network device to forward packets on
  -h, --help                     Print help
  -V, --version                  Print version
```

## ip-to-vsock-raw-outgoing

The ip-to-vsock-raw-outgoing proxy listens on a netfilter queue for raw packets and proxies them to a fixed vsock address. Meant to be used in conjunction with [vsock-to-ip-raw-outgoing](#vsock-to-ip-raw-outgoing) proxy and iptables rules to intercept packets and redirect them into a netfilter queue.

### Usage

```bash
$ ./target/release/ip-to-vsock-raw-outgoing --help
Usage: ip-to-vsock-raw-outgoing --vsock-addr <VSOCK_ADDR> --queue-num <QUEUE_NUM>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address to forward packets to <cid:port>
  -q, --queue-num <QUEUE_NUM>    nfqueue number of the listener <num>
  -h, --help                     Print help
  -V, --version                  Print version
```

## vsock-to-ip-raw-outgoing

The vsock-to-ip-raw-outgoing proxy listens on a vsock address for raw packets and proxies them to a fixed network device. Meant to be used in conjunction with [ip-to-vsock-raw-outgoing](#ip-to-vsock-raw-outgoing) proxy to receive raw packets.

### Usage

```bash
$ ./target/release/vsock-to-ip-raw-outgoing --help
Usage: vsock-to-ip-raw-outgoing --vsock-addr <VSOCK_ADDR>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address to listen on <cid:port>
  -h, --help                     Print help
  -V, --version                  Print version
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
