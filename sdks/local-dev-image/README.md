![Marlin Oyster Logo](./logo.svg)

# Oyster Local Development Image

The oyster local development image packages the basic oyster features like `keygen`, `attestation-server` and `kms-derive-server` required for the local testing of user apps before they deploy them on oyster CVMs. The docker image is built using Nix for reproducibility.

## Build base image

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#musl.sdks.local-dev-image.default
```

This outputs the base image ( '.tar.gz' file) in the default `result/` directory. This image can then be loaded on the local docker daemon using: 
```bash
docker load < result
``` 

## Running the image

The loaded dev image can then be run with the following command:
```bash
docker run --privileged --network=host --rm -it marlinorg/local-dev-image:latest
```

This will start a docker container from the dev image. The container will be started with the above mentioned services mocked for local environment.

## Interacting with the container

Attestation servers running inside the container can be reached via following local endpoints:
```bash
curl http://localhost:1301/attestation/hex
curl http://localhost:1301/attestation/raw
curl http://localhost:1300/attestation/hex
curl http://localhost:1300/attestation/raw
```

## Build a dev image

A local dev image can be built from a `docker-compose.yml` file whose container will then run the services mentioned in the yml file inside it on start up. To achieve this, first copy the `docker-compose.yml` file into this `local-dev-image` directory and use the following commands:
```bash
git add docker-compose.yml
sudo env COMPOSE="/docker-compose.yml" nix build --impure -v .#musl.sdks.local-dev-image.default
```

Load and run the created dev image like mentioned above and interact with the services defined in the yml file running inside the container.

## Build a dev image with custom docker images

Local docker images ( '.tar' files) can also be loaded in the dev image, all of which can then be pulled by the docker daemon inside the dev container to run the `docker-compose.yml` file. To achieve this, copy all the docker images into this `local-dev-image` directory and use the following commands:
```bash
git add *.tar
sudo env DOCKER_IMAGES='[ "/ollama_amd64.tar", "/image.tar" ]' COMPOSE="/docker-compose.yml" nix build --impure -v .#musl.sdks.local-dev-image.default
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
