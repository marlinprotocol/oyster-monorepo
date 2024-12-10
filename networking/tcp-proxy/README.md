![Marlin Oyster Logo](./logo.svg)

# TCP Proxies

This project contains TCP proxies used to bridge between IP interfaces and vsock interfaces. They are primarily used in the salmon family of images. This project contains the following proxies:
- ip-to-vsock
- vsock-to-ip
- ip-to-vsock-transparent
- vsock-to-ip-transparent
- port-to-vsock-transparent

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.networking.tcp-proxy.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## ip-to-vsock

The ip-to-vsock proxy listens on a fixed IP address and proxies any incoming connections to a fixed vsock address.

### Usage

```bash
$ ./target/release/ip-to-vsock --help
Usage: ip-to-vsock --ip-addr <IP_ADDR> --vsock-addr <VSOCK_ADDR>

Options:
  -i, --ip-addr <IP_ADDR>        ip address of the listener side (e.g. 0.0.0.0:4000)
  -v, --vsock-addr <VSOCK_ADDR>  vsock address of the upstream side (e.g. 88:4000)
  -h, --help                     Print help
  -V, --version                  Print version
```

## vsock-to-ip

The vsock-to-ip proxy listens on a fixed vsock address and proxies any incoming connections to a fixed ip address.

### Usage

```bash
$ ./target/release/vsock-to-ip --help
Usage: vsock-to-ip --vsock-addr <VSOCK_ADDR> --ip-addr <IP_ADDR>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address of the listener side (e.g. 88:4000)
  -i, --ip-addr <IP_ADDR>        ip address of the listener side (e.g. 127.0.0.1:4000)
  -h, --help                     Print help
  -V, --version                  Print version
```

## ip-to-vsock-transparent

The ip-to-vsock-transparent proxy listens on a fixed IP address and proxies any incoming connections to a fixed vsock address much like the [ip-to-vsock](#ip-to-vsock) proxy. The key difference being, it fetches the original destination of the connection using `SO_ORIGINAL_DST` and sends it on the vsock connection first before acting as a simple proxy. Meant to be used in conjunction with [vsock-to-ip-transparent](#vsock-to-ip-transparent) proxy and iptables rules to intercept outgoing connections.

### Usage

```bash
$ ./target/release/ip-to-vsock-transparent --help
Usage: ip-to-vsock-transparent --ip-addr <IP_ADDR> --vsock-addr <VSOCK_ADDR>

Options:
  -i, --ip-addr <IP_ADDR>        ip address of the listener side (e.g. 127.0.0.1:1200)
  -v, --vsock-addr <VSOCK_ADDR>  vsock address of the upstream side, usually the other side of the transparent proxy (e.g. 3:1200)
  -h, --help                     Print help
  -V, --version                  Print version
```

## vsock-to-ip-transparent

The vsock-to-ip-transparent proxy listens on a fixed vsock address and proxies any incoming connections to a dynamic IP address much like the [vsock-to-ip](#vsock-to-ip) proxy except the destination address is not fixed. The destination address is obtained from the beginning of the stream after which it connects to the destination and acts as a simple proxy. Meant to be used in conjunction with [ip-to-vsock-transparent](#ip-to-vsock-transparent) proxy.

### Usage

```bash
$ ./target/release/vsock-to-ip-transparent --help
Usage: vsock-to-ip-transparent --vsock-addr <VSOCK_ADDR>

Options:
  -v, --vsock-addr <VSOCK_ADDR>  vsock address of the listener side, usually open to the other side of the transparent proxy (e.g. 3:1200)
  -h, --help                     Print help
  -V, --version                  Print version
```

## port-to-vsock-transparent

The port-to-vsock-transparent proxy listens on a fixed IP address and proxies any incoming connections to a dynamic vsock address much like the [ip-to-vsock](#ip-to-vsock) proxy except the destination port is not fixed. The proxy fetches the original destination of the connection using `SO_ORIGINAL_DST` and proxies it to the vsock on the same port. Meant to be used in conjunction with iptables rules to intercept incoming connections.

### Usage

```bash
$ ./target/release/port-to-vsock-transparent --help
Usage: port-to-vsock-transparent --ip-addr <IP_ADDR> --vsock <VSOCK>

Options:
  -i, --ip-addr <IP_ADDR>  ip address of the listener side (e.g. 127.0.0.1:1200)
  -v, --vsock <VSOCK>      vsock address of the upstream side (e.g. 88:1200)
  -h, --help               Print help
  -V, --version            Print version
```

## Credits

All of them are based on proxies from [tokio](https://tokio.rs/), with the transparent proxies also borrowing from [linkerd](https://linkerd.io/) for `SO_ORIGINAL_DST` related functionality.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).

In addition, it includes code derived from the [tokio](https://tokio.rs/) project, licensed under the MIT License as well as the [linkerd](https://linkerd.io/) project, licensed under the Apache License, Version 2.0.
