![Marlin Oyster Logo](./logo.svg)

# Attestation Verifier

The attestation verifier verifies attestations provided by the [attestation server](https://github.com/marlinprotocol/oyster-attestation-server) containing a secp256k1 public key and signs the response using its own secp256k1 key. Intended to be run inside an enclave to provide cheap attestation verification services.

Once the attestation of the verifier is verified on-chain (very expensive), it enables other enclaves, including other verifiers, to get verified by submitting a simple ECDSA signature from the verifier instead (very cheap). The process essentially extends the chain of trust of the attestation verifier enclave instead of trying to verify the full attestation of the other enclave again.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.attestation.verifier.<output>
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
$ ./target/release/oyster-attestation-verifier --help
Usage: oyster-attestation-verifier --secp256k1-secret <SECP256K1_SECRET> --secp256k1-public <SECP256K1_PUBLIC> --ip <IP> --port <PORT>

Options:
      --secp256k1-secret <SECP256K1_SECRET>
          path to secp256k1 private key file (e.g. /app/secp256k1.sec)
      --secp256k1-public <SECP256K1_PUBLIC>
          path to secp256k1 public key file (e.g. /app/secp256k1.pub)
  -i, --ip <IP>
          server ip (e.g. 127.0.0.1)
  -p, --port <PORT>
          server port (e.g. 1400)
  -h, --help
          Print help
  -V, --version
          Print version
```

## CLI Verification
The attestation verifier also includes a binary to verify an attestation doc locally through the CLI as shown below :- 

```
$ ./target/release/oyster-verify-attestation --help
Usage: oyster-verify-attestation --attestation <ATTESTATION>

Options:
      --attestation <ATTESTATION>  
          path to attestation doc hex string file
  -h, --help                       Print help
  -V, --version                    Print version
```

Above execution will return an error if failing to parse or verify the attestation doc/file. 
If the verification completes successfully, the parsed attestation doc will be printed in below format :- 
```
AttestationDecoded {
    pcrs: [[...], [...], [...]],
    timestamp: '...',
    public_key: [...]
}
```

To generate the attestation hex file, call the corresponding `attestation-server` endpoint inside a running enclave like below:-
```
$ curl <attestation_server_ip:attestation_server_port>/attestation/hex --output attestation.hex
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8938  100  8938    0     0   126k      0 --:--:-- --:--:-- --:--:--  124k
```

## Endpoints

The attestation verifier exposes two verification endpoints which expect the attestation in one of two formats - raw and hex. The formats match the two endpoints of the [attestation server](https://github.com/marlinprotocol/oyster-attestation-server) and the response of the server can just be sent to the verifier as is.

### Raw

##### Endpoint

`/verify/raw`

##### Example

```
$ curl <attestation_server_ip:attestation_server_port>/attestation/raw -vs | curl -H "Content-Type: application/octet-stream" --data-binary @- <attestation_verifier_ip:attestation_verifier_port>/verify/raw -vs
*   Trying <attestation_server_ip:attestation_server_port>...
* Connected to <attestation_server_ip> (<attestation_server_ip>) port <attestation_server_port> (#0)
> GET /attestation/raw HTTP/1.1
> Host: <attestation_server_ip:attestation_server_port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/octet-stream
< content-length: 4468
< date: Sun, 07 Apr 2024 06:36:44 GMT
< 
{ [2682 bytes data]
* Connection #0 to host <attestation_server_ip> left intact
*   Trying <attestation_verifier_ip:attestation_verifier_port>...
* Connected to <attestation_verifier_ip> (<attestation_verifier_ip>) port <attestation_verifier_port> (#0)
> POST /verify/raw HTTP/1.1
> Host: <attestation_verifier_ip:attestation_verifier_port>
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Type: application/octet-stream
> Content-Length: 4468
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 799
< content-type: application/json
< date: Sun, 07 Apr 2024 06:36:44 GMT
< 
* Connection #0 to host <attestation_verifier_ip> left intact
{"signature":"1aaffb1463cfbeb24401267d2ab2661a9695dd0fb294fc4f4e66ad98efa1ece63b79c0bfc5d79c8515abbfb4fa50994b848132d3374821ff09eb22c7af37395e1b","secp256k1_public":"e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb","pcr0":"189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6","pcr1":"5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16","pcr2":"6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa","timestamp":1712471793488,"verifier_secp256k1_public":"e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb"}
```

### Hex

##### Endpoint

`/attestation/hex`

##### Example

```
$ curl <attestation_server_ip:attestation_server_port>/attestation/hex -vs | curl -H "Content-Type: text/plain" -d @- <attestation_verifier_ip:attestation_verifier_port>/verify/hex -vs
*   Trying <attestation_server_ip:attestation_server_port>...
* Connected to <attestation_server_ip> (<attestation_server_ip>) port <attestation_server_port> (#0)
> GET /attestation/hex HTTP/1.1
> Host: <attestation_server_ip:attestation_server_port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: text/plain; charset=utf-8
< content-length: 8936
< date: Sun, 07 Apr 2024 06:44:25 GMT
< 
{ [2681 bytes data]
* Connection #0 to host <attestation_server_ip> left intact
*   Trying <attestation_verifier_ip:attestation_verifier_port>...
* Connected to <attestation_verifier_ip> (<attestation_verifier_ip>) port <attestation_verifier_port> (#0)
> POST /verify/hex HTTP/1.1
> Host: <attestation_verifier_ip:attestation_verifier_port>
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Type: text/plain
> Content-Length: 8936
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 799
< content-type: application/json
< date: Sun, 07 Apr 2024 06:44:25 GMT
< 
* Connection #0 to host <attestation_verifier_ip> left intact
{"signature":"4ed49c703e8deea8dabccbeeb8fe5625776dbbbef4cffbb9c31f84d21e7a0b6c63707aade102548cc05e6de3a49469b96c700f5b8709e75ec050061ac69dbb621c","secp256k1_public":"e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb","pcr0":"189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6","pcr1":"5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16","pcr2":"6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa","timestamp":1712472254392,"verifier_secp256k1_public":"e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb"}
```

## Response format

```json
{
    "signature": "...",
    "secp256k1_public": "...",
    "pcr0": "...",
    "pcr1": "...",
    "pcr2": "...",
    "timestamp": ...,
    "verifier_secp256k1_public": "..."
}
```

The verifier responds with JSON with the following fields:
- `signature`: signature provided by the verifier
- `secp256k1_public`: public key that was encoded in the attestation
- `pcr0`: PCR0 that was encoded in the attestation
- `pcr1`: PCR1 that was encoded in the attestation
- `pcr2`: PCR2 that was encoded in the attestation
- `timestamp`: timestamp that was encoded in the attestation
- `verifier_secp256k1_public`: public key of the verifier corresponding to the signature

## Signature format

The verifier creates the signature as per the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) standard.

#### EIP-712 domain

```typescript
struct EIP712Domain {
    string name = "marlin.oyster.AttestationVerifier",
    string version = "1",
}
```

The `chainId`, `verifyingContract` and `salt` fields are omitted because we do not see any significant replay concerns in allowing the signature to be verified on any contract on any chain.

#### Message struct

```typescript
struct Attestation {
    bytes enclavePubKey;
    bytes PCR0;
    bytes PCR1;
    bytes PCR2;
    uint256 timestampInMilliseconds;
}
```

## Verification

It is designed to be verified by the following solidity code (taken from the [AttestationVerifier](https://github.com/marlinprotocol/oyster-contracts/blob/master/contracts/AttestationVerifier.sol#L230) contract):

```solidity
bytes32 private constant DOMAIN_SEPARATOR =
    keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("marlin.oyster.AttestationVerifier"),
            keccak256("1")
        )
    );

bytes32 private constant ATTESTATION_TYPEHASH =
    keccak256("Attestation(bytes enclavePubKey,bytes PCR0,bytes PCR1,bytes PCR2,uint256 timestampInMilliseconds)");

function _verify(bytes memory signature, Attestation memory attestation) internal view {
    bytes32 hashStruct = keccak256(
        abi.encode(
            ATTESTATION_TYPEHASH,
            keccak256(attestation.enclavePubKey),
            keccak256(attestation.PCR0),
            keccak256(attestation.PCR1),
            keccak256(attestation.PCR2),
            attestation.timestampInMilliseconds
        )
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

    address signer = ECDSA.recover(digest, signature);

    ...
}
```

## Running unit tests
Before pushing any changes, try to make sure that no existing functionalities are breaking by running the unit tests. Tests require fresh attestation so update the sample data present in `src/test/` directory by interacting with a running oyster enclave's attestation server (as described above).
```
cargo test
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
