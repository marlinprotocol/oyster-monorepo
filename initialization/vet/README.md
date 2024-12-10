![Marlin Oyster Logo](./logo.svg)

# Vet

Curl-like utility to make http requests over vsocks.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.initialization.vet.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```bash
$ ./target/release/vet --help
Usage: vet --url <URL>

Options:
  -u, --url <URL>  url to query
  -h, --help       Print help
  -V, --version    Print version
```

## Example

```
$ vet --url 3:1500/oyster/job
0x1234567812345678123456781234567812345678123456781234567812345678
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
