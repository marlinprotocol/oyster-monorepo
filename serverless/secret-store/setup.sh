#!/bin/sh

set -e

whoami

# Setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

# Adding a default route
ip route add default dev lo src 127.0.0.1
route -n

# iptables rules to route traffic to transparent proxy
update-alternatives --set iptables /usr/sbin/iptables-legacy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:1200
iptables -L -t nat

# Generate ecdsa key
/app/keygen-secp256k1 --secret /app/ecdsa.sec --public /app/ecdsa.pub

# Copy workerd to correct place
mkdir /app/store
ls -lath /app/store

# Starting supervisord
cat /etc/supervisord.conf
/app/supervisord
