![Marlin Oyster Logo](./logo.svg)

# Init Params Decoder

This project provides a decoder for initialization parameters for enclaves. It is expected to be used inside enclaves to decode the initialization parameters and extract them onto the enclave filesystem inside the `/init-params` directory.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.initialization.init-params-decoder.<output>
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
./target/release/init-params-decoder --help
Usage: init-params-decoder [OPTIONS]

Options:
      --init-params-path <INIT_PARAMS_PATH>
          Init params file [default: /app/init-params]
      --derive-endpoint <DERIVE_ENDPOINT>
          Derive server endpoint [default: http://127.0.0.1:1100]
      --output-dir <OUTPUT_DIR>
          Directory to write the decoded params into, the digest always uses /init-params [default: /init-params]
      --key-fetch-timeout-secs <KEY_FETCH_TIMEOUT_SECS>
          How long to keep retrying the derive server for the decryption key, only used if there are encrypted params [default: 600]
  -h, --help
          Print help
```

The derive server is contacted only if at least one param has `should_decrypt` set. The request is retried with backoff till the timeout runs out, nothing is written if the key could not be fetched.

## Example

Given init params which looks something like this:
```json
{
  "digest": "p9fbHwysAlEuutj8HmMbDyrbXApuLI3xzdVqJR4OOx4=",
  "params": [
    {
      "path": "hello/hello",
      "contents": "hello",
      "should_attest": true,
      "should_decrypt": false
    },
    {
      "path": "Cargo.toml",
      "contents": "5xOFcLzmXtdZkP+rU/d1wAEsWpH6VDXAaM0UTgXAblBliUzmDBDVZd/qcxa2293+xPwoNOpeu9ZTDpgVXacM7iBaRBGNonoalIMmUH+5YB6rh+YKigqhbivt/EMcNyYJL+zNmiHgT2Rk76S7A6BvMnHLKJG81zOzPzW2Cp40fTYWoV336n2oExpM5V8zjmEez1qWCHOWp3ByIJyGD7vBGHqoT43fUtQCfawIXwZ0ic+bw99qzfrfUS4bz/rEJtJRWr40TO8FgTETjOuNerG/vSUZ+rnU3PV4k8Z6nQ5GU0Puo0HP1kq0MrLZcIGTpwTcee/Do4xrxhfiKMoOdX5JB+2Kpy4AX0idv2k2MIltJR1HJ2eplv27li6xgeFvZEB4dTgUm78JrsDM2Pp8mlQdrBln6vuzCBtpGWQEUhqyfHXCPKfqfShWg/IY1NrkEdvkx0hOtFxxOZ/q7Xg4pgf4Ekynznyq+XjhZdeX4/0HaOaD8/hfWrOTcKKLcWjVfjSqvNpd8lBVjMGxqcps+cBlXNkFhwu3icXYQmFAQZFnakdbUHn1Obxf0/zabx1L1dAjKu5EsF0sg2SUbq5GaLIYaClFnWBD29dPiJLpbUaR4OZMHHkn/LDOR7eer/nyrw58AR4rh8SlGiE7JIqkzXqDse/DSacpUTAb4TmDPdrbDkxNshx/sXAsVc5wuK7Lt+VJ3xjChJ/PSbNbJit3hstc490YaOlRDpXdWRY4Cq6EnDI2ZHuGOTuEz7aSKPrpjpRdNDztkSXwPcEedJOC+ZCBJIffdaG96DeciahGbK6Po4piam4kh9Vxz4DzOnbupxdpk1haqjEqLznoOttfvcT0439XEww6AVrmr6tvhVAJXaUZRSYe6038A6vmf/352reg8bSnLxRzt95UQw4GO//O+fu2KUzEwX4nAyW5YAEHNM7LLWfgkUbgS+dU2kHCPq/OekZmbmQeWYLL/Rg/2A8=",
      "should_attest": true,
      "should_decrypt": true
    }
  ]
}
```

The decoder will create the following files:
- `/init-params/hello/hello` with `hello` as the content
- `/init-params/Cargo.toml` with decrypted contents of the `Cargo.toml` file

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
