#!/bin/sh

set -e

# Setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

# Adding a default route
ip route add default dev lo src 127.0.0.1
route -n

# iptables rules to route traffic to transparent proxy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:1200
iptables -L -t nat

# Generate ecdsa key
/app/keygen-secp256k1 --secret /app/ecdsa.sec --public /app/ecdsa.pub

# Copy workerd to correct place
mkdir /app/runtime
mv /app/workerd /app/runtime/
ls -lath /app/runtime

# Create secret store directory
mkdir /app/store
ls -lath /app/store

# Set up cgroups
cgexec -h
mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup
/app/cgroupv2_setup.sh

# Starting supervisord
cat /etc/supervisord.conf
/app/supervisord
