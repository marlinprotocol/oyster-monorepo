![Marlin Oyster Logo](./logo.svg)

# Kernels

Enclaves image require a kernel. This project builds Amazon Linux kernels using [aws-nitro-enclaves-sdk-bootstrap](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap) and includes patches adding/removing kernel features to serve different use cases.

## Vanilla

The vanilla kernel is built without any real modifications. It is used in the Salmon family of images.

### Patches applied

- [build.patch](./build.patch): allow cross platform builds using `--system`

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kernels.vanilla.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs (derivation):
- `default`

Supported outputs (path only):
- `kernel`
- `kernelConfig`
- `init`
- `nsmKo`

## Tuna

The tuna kernel enables kernel support for nfqueue and ipset. It is used in the Tuna family of images.

### Patches applied

- [build.patch](./build.patch): allow cross platform builds using `--system`
- [tuna.patch](./tuna.patch): enable kernel flags for nfqueue and ipset

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kernels.tuna.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs (derivation):
- `default`

Supported outputs (path only):
- `kernel`
- `kernelConfig`
- `init`
- `nsmKo`

## Serverless

The serverless kernel disables cgroups setup in the init binary so it can be done later during the boot process. It is used by the serverless executors.

### Patches applied

- [build.patch](./build.patch): allow cross platform builds using `--system`
- [serverless.patch](./serverless.patch): disable cgroups setup in init

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kernels.serverless.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs (derivation):
- `default`

Supported outputs (path only):
- `kernel`
- `kernelConfig`
- `init`
- `nsmKo`

## License

This project is licensed under the GNU GPLv2 or any later version. See [LICENSE.txt](./LICENSE.txt).
