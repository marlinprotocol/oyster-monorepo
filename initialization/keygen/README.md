![Marlin Oyster Logo](./logo.svg)

# Keygen

Generate keypairs for use in other applications. The repository contains generators for the following cryptosystems:
- ed25519
- secp256k1

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.initialization.keygen.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## ed25519

### Usage

```bash
$ ./target/release/keygen-ed25519 --help
Usage: keygen-ed25519 --secret <SECRET> --public <PUBLIC>

Options:
  -s, --secret <SECRET>  path to private key file
  -p, --public <PUBLIC>  path to public key file
  -h, --help             Print help
  -V, --version          Print version
```

### Example

keygen-ed25519 generates a ed25519 key pair and stores it in the file paths provided. The secret key and public key are stored as bytes, with a size of 64 and 32 respectively.

```bash
$ ./target/release/keygen-ed25519 --secret ed25519.sec --public ed25519.pub
private key: ed25519.sec, public key: ed25519.pub
Generation successful!
$ xxd ed25519.sec
00000000: d470 d794 7b10 a3f1 e255 fc6d 562b a953  .p..{....U.mV+.S
00000010: adaf 2957 9798 c646 603b 4c4e c197 aeb0  ..)W...F`;LN....
00000020: c583 a2b0 dc98 f152 1774 b5c1 51e2 885d  .......R.t..Q..]
00000030: f10e cab1 ea38 b17d ac05 8814 89d3 b156  .....8.}.......V
$ xxd ed25519.pub
00000000: c583 a2b0 dc98 f152 1774 b5c1 51e2 885d  .......R.t..Q..]
00000010: f10e cab1 ea38 b17d ac05 8814 89d3 b156  .....8.}.......V
```

## secp256k1

### Usage

```bash
$ ./target/release/keygen-secp256k1 --help
Usage: keygen-secp256k1 --secret <SECRET> --public <PUBLIC>

Options:
  -s, --secret <SECRET>  path to private key file
  -p, --public <PUBLIC>  path to public key file
  -h, --help             Print help
  -V, --version          Print version
```

### Example

keygen-secp256k1 generates a secp256k1 key pair and stores it in the file paths provided. The secret key and public key are stored as bytes, with a size of 32 and 64 respectively. Note that the public key is stored uncompressed _without_ the `0x04` prefix byte.

```bash
$ ./target/release/keygen-secp256k1 --secret secp256k1.sec --public secp256k1.pub
private key: secp256k1.sec, public key: secp256k1.pub
Generation successful!
$ xxd secp256k1.sec 
00000000: 98ef bf0a 6ffa 9fb8 c9ec 5c95 8d8d bead  ....o.....\.....
00000010: a169 a3b5 026b a234 a37c 23f0 09b3 62d9  .i...k.4.|#...b.
$ xxd secp256k1.pub
00000000: 38b4 6703 1fdd 557a 70cc 701d b26c a40b  8.g...Uzp.p..l..
00000010: af91 771b efeb bf9a 1813 bc49 3687 d79d  ..w........I6...
00000020: bef9 f73a 8239 5593 3618 6d6d bf01 2cb4  ...:.9U.6.mm..,.
00000030: 7161 50c5 801a 24fe 9bd3 83a4 ca79 655d  qaP...$......ye]
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
