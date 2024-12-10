#!/bin/sh
set -e

MAX_RETRIES=50
RETRY_COUNT=0

# Wait for Docker daemon with timeout
while ! docker info >/dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "[docker-compose-start.sh] ERROR: Docker daemon failed to start after ${MAX_RETRIES} attempts"
        exit 1
    fi
    echo "[docker-compose-start.sh] Waiting for Docker daemon (attempt ${RETRY_COUNT}/${MAX_RETRIES})..."
    sleep 1
done

echo "[docker-compose-start.sh] Docker daemon is running."

# Load multiple Docker images with error handling
for image_tar in /app/docker-images/*.tar; do
    if ! docker load -i "$image_tar"; then
        echo "[docker-compose-start.sh] ERROR: Failed to load Docker image from $image_tar"
        exit 1
    fi
    echo "[docker-compose-start.sh] Docker image loaded successfully from $image_tar."
done

# Verify docker-compose exists
if ! command -v docker compose >/dev/null 2>&1; then
    echo "[docker-compose-start.sh] ERROR: docker compose not found"
    exit 1
fi

# Start docker-compose with error handling
if ! docker compose -f /app/docker-compose.yml up --remove-orphans; then
    echo "[docker-compose-start.sh] ERROR: Failed to start Docker Compose services"
    exit 1
fi
