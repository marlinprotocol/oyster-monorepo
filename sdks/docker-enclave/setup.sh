#!/bin/sh

set -e

# query the init server on the host, it might not be listening yet
# retry for about a minute before giving up
fetch() {
    attempt=1
    until /app/vet --url "$1" > "$2.tmp"; do
        if [ "$attempt" -ge 30 ]; then
            echo "[setup.sh] could not fetch $1, giving up"
            return 1
        fi
        echo "[setup.sh] could not fetch $1, retrying"
        attempt=$((attempt + 1))
        sleep 2
    done
    mv "$2.tmp" "$2"
}

# query ip of instance and store
fetch vsock://3:1300/instance/ip /app/ip.txt
cat /app/ip.txt && echo

# query init params for enclave and store
fetch vsock://3:1300/oyster/init-params /app/init-params

# extract digest, skip if empty
# no pipes here, a jq or base64 failure has to stop the boot
mkdir /init-params
ls -lath /app
if [ -s /app/init-params ]; then
    jq -e -r '.digest' /app/init-params > /app/init-params-digest.b64
    base64 -d /app/init-params-digest.b64 > /app/init-params-digest
    cat /app/init-params-digest
fi

# extend pcr16 with the digest and lock it, pcr16 stays zero when the job
# has no init params
if [ -s /app/init-params-digest ]; then
    /app/pcr-extender --index 16 --contents-path /app/init-params-digest
fi
/app/pcr-locker --index 16

ip=$(cat /app/ip.txt)

# set up loopback
ip addr add 127.0.0.1/8 dev lo
ip link set lo up

# set up bridge
ip link add name br0 type bridge
ip addr add $ip/32 dev br0
ip link set dev br0 mtu 9001
ip link set dev br0 up

# adding a default route via the bridge
ip route add default dev br0 src $ip

# localhost dns
echo "127.0.0.1 localhost" > /etc/hosts

ip link
ip addr
ip route
cat /etc/hosts

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

# Run supervisor first, no programs should be running yet
cat /etc/supervisord.conf
/app/supervisord &
SUPERVISOR_PID=$!
sleep 1
echo "status"
/app/supervisord ctl -c /etc/supervisord.conf status

# start proxies
/app/supervisord ctl -c /etc/supervisord.conf start ip-to-vsock-raw-outgoing
/app/supervisord ctl -c /etc/supervisord.conf start vsock-to-ip-raw-incoming

# start dnsproxy
/app/supervisord ctl -c /etc/supervisord.conf start dnsproxy

# generate identity key
/app/keygen-x25519 --secret /app/id.sec --public /app/id.pub
/app/keygen-secp256k1 --secret /app/ecdsa.sec --public /app/ecdsa.pub

# start attestation servers
/app/supervisord ctl -c /etc/supervisord.conf start attestation-server
/app/supervisord ctl -c /etc/supervisord.conf start attestation-server-ecdsa

sleep 2

# start derive server
/app/supervisord ctl -c /etc/supervisord.conf start derive-server

# process init params into their constituent files
# needs the derive server only if a param is encrypted and waits for it by itself
/app/init-params-decoder

# give the derive server some time to get its seed so apps can use it from the start
# the kms being down should not stop the boot, carry on after 30 seconds
attempt=1
until wget -q -T 2 -O /dev/null "http://127.0.0.1:1100/derive/x25519?path=oyster.boot-probe"; do
    if [ "$attempt" -ge 30 ]; then
        echo "[setup.sh] derive server is not ready, continuing without it"
        break
    fi
    echo "[setup.sh] Waiting for derive server..."
    attempt=$((attempt + 1))
    sleep 1
done

# start derive server contract if contract address and root server config are present
if [ -f /init-params/contract-address ] && [ -f /init-params/root-server-config.json ]; then
    /app/supervisord ctl -c /etc/supervisord.conf start derive-server-contract
fi

# Start the Docker daemon
/app/supervisord ctl -c /etc/supervisord.conf start docker

# Wait for Docker daemon to be ready
until docker info >/dev/null 2>&1; do
    echo "[setup.sh] Waiting for Docker daemon..."
    sleep 1
done

# load the docker images built into the enclave image
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

wait $SUPERVISOR_PID
