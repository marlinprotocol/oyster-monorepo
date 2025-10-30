#!/bin/sh

set -e

# query ip of instance and store
/app/vet --url vsock://3:1300/instance/ip > /app/ip.txt
cat /app/ip.txt && echo

# query init params for enclave and store
/app/vet --url vsock://3:1300/oyster/init-params > /app/init-params

# extract digest, skip if empty
mkdir /init-params
ls -lath /app
if [ -s /app/init-params ]; then
    cat /app/init-params | jq -e -r '.digest' | base64 -d > /app/init-params-digest
    cat /app/init-params-digest
fi

# # extend pcr16 with the digest and lock it
# /app/pcr-extender --index 16 --contents-path /app/init-params-digest
# /app/pcr-locker --index 16

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
sleep 10

# # Fetch raw binary key from your endpoint
# key_bin=$(curl -s http://127.0.0.1:1100/derive/secp256k1?path=nfstest)

# # Convert binary to hex
# key_hex=$(echo -n "$key_bin" | xxd -p | tr -d '\n')

# # Print or store master key
# echo "Derived master key (hex): $key_hex"

# process init params into their constituent files
/app/init-params-decoder

# start derive server contract if contract address and root server config are present
if [ -f /init-params/contract-address ] && [ -f /init-params/root-server-config.json ]; then
    /app/supervisord ctl -c /etc/supervisord.conf start derive-server-contract
fi

echo "Mounting remote nfs directory to /app/nfs/"
mount -vvv -t nfs4 -o nolock,noresvport,vers=4 3.111.219.88:/home/ubuntu/nfs_test /app/nfs-encrypted

sleep 5

# --- Configuration ---
SERVER_URL="http://127.0.0.1:1100/derive/secp256k1?path=nfstest"
ENCRYPTED_DIR="/app/nfs-encrypted"
DECRYPTED_DIR="/app/decrypted"
CONF_FILE="$ENCRYPTED_DIR/gocryptfs.conf"
passfile="/app/pass.txt"

echo "[INFO] Deriving master key from enclave..."
key_hex=$(curl -s "$SERVER_URL" | xxd -p | tr -d '\n')

if [ -z "$key_hex" ]; then
  echo "[ERROR] Failed to derive master key from enclave service" >&2
  exit 1
fi

if [ ${#key_hex} -ne 64 ]; then
  echo "[WARN] Derived key length is ${#key_hex} hex chars (expected 64)"
fi

echo "Derived master key (hex): $key_hex"

# write without a trailing newline
printf '%s' "$key_hex" > $passfile


if [ ! -f "$CONF_FILE" ]; then
  echo "[INFO] No gocryptfs.conf found. Initializing new filesystem..."
  
  # Initialize with temporary password to create config
  gocryptfs -init "$ENCRYPTED_DIR" -passfile $passfile

else
  echo "[INFO] Existing config found. Skipping initialization."
fi

echo "[INFO] gocryptfs init done"

# --- Mount filesystem ---
if mountpoint -q "$DECRYPTED_DIR"; then
  echo "[INFO] Already mounted: $DECRYPTED_DIR"
else
  echo "[INFO] Mounting gocryptfs filesystem..."
  gocryptfs -daemonize "$ENCRYPTED_DIR" "$DECRYPTED_DIR" -passfile $passfile
  echo "[INFO] Mount successful at $DECRYPTED_DIR"
fi

echo "gocryptfs mounting done"

echo "hello world" > /app/decrypted/test.txt


# Start the Docker daemon
/app/supervisord ctl -c /etc/supervisord.conf start docker

# Wait for Docker daemon to be ready
until docker info >/dev/null 2>&1; do
    echo "[setup.sh] Waiting for Docker daemon..."
    sleep 1
done

# start docker compose
/app/supervisord ctl -c /etc/supervisord.conf start compose

wait $SUPERVISOR_PID