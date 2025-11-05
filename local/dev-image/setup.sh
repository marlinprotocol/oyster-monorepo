#!/bin/sh

set -e

# store ip
ip route | awk '/default/ { print $3 }' > /app/ip.txt
cat /app/ip.txt && echo

# store job id as container id
cat /etc/hostname > /app/job.txt
cat /app/job.txt && echo

# Run supervisor first, no programs should be running yet
cat /etc/supervisord.conf
/app/supervisord &
SUPERVISOR_PID=$!
echo "status"
/app/supervisord ctl -c /etc/supervisord.conf status

# Start the Docker daemon
/app/supervisord ctl -c /etc/supervisord.conf start docker

# generate identity keys
/app/keygen-x25519 --secret /app/id.sec --public /app/id.pub
/app/keygen-secp256k1 --secret /app/ecdsa.sec --public /app/ecdsa.pub

# start mock attestation servers
/app/supervisord ctl -c /etc/supervisord.conf start attestation-server
/app/supervisord ctl -c /etc/supervisord.conf start attestation-server-ecdsa

# start mock derive server
/app/supervisord ctl -c /etc/supervisord.conf start derive-server

if [ -e "/app/docker-compose.yml" ]; then 
    # Wait for Docker daemon to be ready
    until docker info >/dev/null 2>&1; do
        echo "[setup.sh] Waiting for Docker daemon..."
        sleep 1
    done

    # Load Docker images if any exist
    if [ "$(ls -A /app/docker-images 2>/dev/null)" ]; then
        for image_tar in /app/docker-images/*.tar; do
            if ! docker load -i "$image_tar"; then
                echo "[setup.sh] ERROR: Failed to load Docker image from $image_tar"
                exit 1
            fi
            echo "[setup.sh] Docker image loaded successfully from $image_tar."
        done
    else
        echo "[setup.sh] No Docker images to load"
    fi

    # start docker compose
    /app/supervisord ctl -c /etc/supervisord.conf start compose
fi    

wait $SUPERVISOR_PID