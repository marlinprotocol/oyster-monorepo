FROM ubuntu:22.04

ARG TARGETARCH

RUN apt-get update -y
RUN apt-get install apt-utils -y
RUN apt-get install wget -y
RUN apt-get autoclean && apt-get autoremove
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

# workerd runtime binary
RUN wget -O workerd https://github.com/marlinprotocol/oyster-monorepo/raw/refs/heads/master/serverless/executor/runtime/workerd
RUN chmod +x workerd

# Copy your capnp configuration file into the container
COPY config.capnp ./

# Entry point
ENTRYPOINT [ "/bin/sh", "-c", "/app/workerd serve /app/config.capnp --verbose"]
