![Marlin Oyster Logo](./logo.svg)

# PCR utils

This project provides utilities for extending and locking custom PCRs.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.initialization.pcr-utils.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## PCR extender

The PCR extender allows extension of a PCR at a given index with the contents of a given file.

### Usage

```bash
$ ./target/release/pcr-extender --help
Extend PCRs

Usage: pcr-extender --index <INDEX> --contents-path <CONTENTS_PATH>

Options:
  -i, --index <INDEX>                  PCR index, should be within [16, 31] inclusive
  -c, --contents-path <CONTENTS_PATH>  path to file whose contents to extend the PCR with
  -h, --help                           Print help
  -V, --version                        Print version
```

### Example

```bash
$ ./target/release/pcr-extender --index 16 --contents-path /app/init-params-digest
```

The command extends PCR16 with the contents of `/app/init-params-digest`.

## PCR locker

The PCR locker allows locking of a PCR at a given index, which makes it unmodifiable and includes it in subsequent attestations.

### Usage

```bash
$ ./target/release/pcr-locker --help
Lock PCRs

Usage: pcr-locker --index <INDEX>

Options:
  -i, --index <INDEX>  PCR index, should be within [16, 31] inclusive
  -h, --help           Print help
  -V, --version        Print version
```

### Example

```bash
$ ./target/release/pcr-locker --index 16
```

The command locks PCR16 which is then included in future attestations.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
