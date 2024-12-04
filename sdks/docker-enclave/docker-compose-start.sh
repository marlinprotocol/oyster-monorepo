#!/bin/sh

# Wait for the Docker daemon to start
while ! docker info >/dev/null 2>&1; do
    echo "[docker-compose-start.sh] Waiting for the Docker daemon to start..."
    sleep 1
done

echo "[docker-compose-start.sh] Docker daemon is running."

# Load Docker image from tar file
docker load -i /app/docker-image.tar
echo "[docker-compose-start.sh] Docker image loaded."

# Start docker-compose
docker compose -f /app/docker-compose.yml up 