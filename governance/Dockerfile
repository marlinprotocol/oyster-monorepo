# ---------- 1) Build stage ----------
    FROM rust:1-bookworm AS builder

    # Create a new empty shell project
    WORKDIR /app
    
    # Copy manifests first (for Docker layer caching)
    COPY Cargo.toml Cargo.lock ./
    # If you have a workspace, also copy the workspace members' Cargo.toml files here.
    
    # Copy source
    COPY src ./src
    
    # Build in release mode
    RUN cargo build --release --features dirty_kms,contract_image_id_source
    
    # ---------- 2) Runtime stage ----------
    FROM debian:bookworm-slim AS runtime
    
    # Install minimal runtime deps (ca-certificates often useful for HTTP clients)
    RUN apt-get update && \
        apt-get install -y --no-install-recommends ca-certificates && \
        rm -rf /var/lib/apt/lists/*
    
    WORKDIR /app

    # Non-root user for safety
    RUN useradd -m appuser \
        && chown -R appuser:appuser /app
    
    # Change this to your actual binary name if different
    ARG BIN_NAME=governance
    
    # Copy the compiled binary from the builder stage
    COPY --from=builder /app/target/release/${BIN_NAME} /usr/local/bin/app
    
    USER appuser
    
    # The port your app listens on
    EXPOSE 3001
    
    # Optional: set any env vars here
    # ENV RUST_LOG=info
    
    # Start the app
    CMD ["app"]