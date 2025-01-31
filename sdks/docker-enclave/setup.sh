#!/bin/sh

set -e

# Start the Docker daemon in the background
/bin/dockerd --iptables=false &

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

# Stop the Docker daemon
if [ -f /var/run/docker.pid ]; then
    kill $(cat /var/run/docker.pid)
    # Wait for Docker to stop
    while [ -f /var/run/docker.pid ]; do
        sleep 1
    done
fi

rm -f /var/run/docker.pid
rm -f /var/run/docker.sock

# query ip of instance and store
/app/vet --url vsock://3:1300/instance/ip > /app/ip.txt
cat /app/ip.txt && echo

# query job id for enclave and store
/app/vet --url vsock://3:1300/oyster/job > /app/job.txt
cat /app/job.txt && echo

# query init params for enclave and store
/app/vet --url vsock://3:1300/oyster/init-params > /app/init-params
/app/vet --url vsock://3:1300/oyster/extra-init-params > /app/extra-init-params

ip=$(cat /app/ip.txt)

# setting an address for loopback
ifconfig lo $ip mtu 9001
ip addr add $ip dev lo

# localhost dns
echo "127.0.0.1 localhost" > /etc/hosts

ifconfig
ip addr
cat /etc/hosts

# adding a default route
ip route add default dev lo src $ip
route -n

# create ipset with all "internal" (unroutable) addresses
ipset create internal hash:net
ipset add internal 0.0.0.0/8
ipset add internal 10.0.0.0/8
ipset add internal 100.64.0.0/10
ipset add internal 127.0.0.0/8
ipset add internal 169.254.0.0/16
ipset add internal 172.16.0.0/12
ipset add internal 192.0.0.0/24
ipset add internal 192.0.2.0/24
ipset add internal 192.88.99.0/24
ipset add internal 192.168.0.0/16
ipset add internal 198.18.0.0/15
ipset add internal 198.51.100.0/24
ipset add internal 203.0.113.0/24
ipset add internal 224.0.0.0/4
ipset add internal 233.252.0.0/24
ipset add internal 240.0.0.0/4
ipset add internal 255.255.255.255/32

# create ipset with the ports supported for routing
ipset create portfilter bitmap:port range 0-65535
ipset add portfilter 1024-61439
ipset add portfilter 80
ipset add portfilter 443

# iptables rules to route traffic to a nfqueue to be picked up by the proxy
iptables -A OUTPUT -p tcp -s $ip -m set --match-set portfilter src -m set ! --match-set internal dst -j NFQUEUE --queue-num 0
iptables -t nat -vL
iptables -vL

# generate identity key
/app/keygen-ed25519 --secret /app/id.sec --public /app/id.pub
/app/keygen-secp256k1 --secret /app/ecdsa.sec --public /app/ecdsa.pub

# your custom setup goes here

# starting supervisord
cat /etc/supervisord.conf
/app/supervisord
