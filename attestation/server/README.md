![Marlin Oyster Logo](./logo.svg)

# Attestation Server

The attestation server generates attestations using the AWS Nitro Secure Module (NSM) API and makes them available using a HTTP server. It includes a public key that can be used to extend the chain of trust of the attestation by other enclave applications. Intended to be run inside an enclave.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.attestation.server.<output>
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
$ ./target/release/oyster-attestation-server --help
http server for handling attestation document requests

Usage: oyster-attestation-server --ip-addr <IP_ADDR> --pub-key <PUB_KEY> --init-params <INIT_PARAMS>

Options:
  -i, --ip-addr <IP_ADDR>          ip address of the server (e.g. 127.0.0.1:1300)
  -p, --pub-key <PUB_KEY>          path to public key file (e.g. /app/id.pub)
      --init-params <INIT_PARAMS>  path to init params file (e.g. /app/init-params)
  -h, --help                       Print help
  -V, --version                    Print version
```

## Endpoints

The attestation server exposes attestations through two endpoints which encode the attestation in one of two format - raw and hex. The raw format is a binary format with the raw bytes of the attestation. The hex format is the same attestation, simply hex encoded. Therefore, the raw format is about half the size of the other while the hex format is ASCII letters and numbers only.

### Raw

##### Endpoint

`/attestation/raw`

##### Example

```
$ curl <ip:port>/attestation/raw -vs | xxd
*   Trying <ip:port>...
* Connected to <ip> (<ip>) port <port> (#0)
> GET /attestation/raw HTTP/1.1
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

##### Example

```
$ curl <ip:port>/attestation/hex -vs
*   Trying <ip:port>...
* Connected to <ip> (<ip>) port <port> (#0)
> GET /attestation/hex HTTP/1.1
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
