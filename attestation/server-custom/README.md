![Marlin Oyster Logo](./logo.svg)

# Attestation Server - Custom

The custom attestation server generates attestations using the AWS Nitro Secure Module (NSM) API and makes them available using a HTTP server. It expects callers to provide one or more of a public key, user data and nonce which are included in the attestation.

IMPORTANT: DO NOT expose this server to external access or untrusted enclave components unless you really know what you are doing, it is meant to be exposed purely to trusted applications inside the enclave as a way of accessing the NSM API over HTTP. Otherwise, it breaks the security model assumed by most enclaves since attestations can potentially be generated with public keys corresponding to private keys external to the enclave as well as with secrets which should never be exposed outside the enclave.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.attestation.server-custom.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```
$ ./target/release/oyster-attestation-server-custom --help
http server for handling attestation document requests

Usage: oyster-attestation-server-custom [OPTIONS]

Options:
  -i, --ip-addr <IP_ADDR>  ip address of the server [default: 127.0.0.1:1350]
  -h, --help               Print help
  -V, --version            Print version

```

## Endpoints

The attestation server exposes attestations through two endpoints which encode the attestation in one of two format - raw and hex. The raw format is a binary format with the raw bytes of the attestation. The hex format is the same attestation, simply hex encoded. Therefore, the raw format is about half the size of the other while the hex format is ASCII letters and numbers only.

Both endpoints accept query parameters which can be used to set the public key, user data and nonce in the attestation document.

### Raw

##### Endpoint

`/attestation/raw`

##### Query params

- `public_key`: Optional, hex encoded public key without the `0x` prefix that is included in the `public_key` field of the attestation after being decoded into raw bytes
- `user_data`: Optional, hex encoded user data without the `0x` prefix that is included in the `user_data` field of the attestation after being decoded into raw bytes
- `nonce`: Optional, hex encoded nonce without the `0x` prefix that is included in the `nonce` field of the attestation after being decoded into raw bytes

While all query parameters are optional, any useful attestation will likely include at least the public key to extend the chain of trust.

##### Example

```
$ curl '<ip:port>/attestation/raw?public_key=<public_key>&user_data=<user_data>&nonce=<nonce>' -vs | xxd
*   Trying <ip:port>...
* Connected to <ip> (<ip>) port <port> (#0)
> GET /attestation/raw?public_key=<public_key>&user_data=<user_data>&nonce=<nonce> HTTP/1.1
> Host: <ip:port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/octet-stream
< content-length: 4466
< date: Sat, 06 Apr 2024 07:28:41 GMT
< 
{ [2682 bytes data]
* Connection #0 to host <ip> left intact
00000000: 8444 a101 3822 a059 1106 a969 6d6f 6475  .D..8".Y...imodu
00000010: 6c65 5f69 6478 2769 2d30 6631 6364 3737  le_idx'i-0f1cd77
00000020: 6433 3766 6438 6263 6339 2d65 6e63 3031  d37fd8bcc9-enc01
00000030: 3865 3761 6136 3165 3230 3430 6666 6664  8e7aa61e2040fffd
00000040: 6967 6573 7466 5348 4133 3834 6974 696d  igestfSHA384itim
00000050: 6573 7461 6d70 1b00 0001 8eb2 4f18 9864  estamp......O..d
...
...
```

### Hex

##### Endpoint

`/attestation/hex`

##### Query params

- `public_key`: Optional, hex encoded public key without the `0x` prefix that is included in the `public_key` field of the attestation after being decoded into raw bytes
- `user_data`: Optional, hex encoded user data without the `0x` prefix that is included in the `user_data` field of the attestation after being decoded into raw bytes
- `nonce`: Optional, hex encoded nonce without the `0x` prefix that is included in the `nonce` field of the attestation after being decoded into raw bytes

While all query parameters are optional, any useful attestation will likely include at least the public key to extend the chain of trust.

##### Example

```
$ curl '<ip:port>/attestation/hex?public_key=<public_key>&user_data=<user_data>&nonce=<nonce>' -vs | xxd
*   Trying <ip:port>...
* Connected to <ip> (<ip>) port <port> (#0)
> GET /attestation/hex?public_key=<public_key>&user_data=<user_data>&nonce=<nonce> HTTP/1.1
> Host: <ip:port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: text/plain; charset=utf-8
< content-length: 8932
< date: Sat, 06 Apr 2024 08:22:00 GMT
< 
8444a1013822a0591106a9696d6f64756c655f69647827692d3066316364...
...
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
