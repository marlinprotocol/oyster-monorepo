#!/bin/bash

links=$(ip -o link show | grep -i 'ens' | awk -F': ' '{print $2}')
rt_tables_file="/etc/iproute2/rt_tables"

# clean all rows containing ens* from rt_tables_file
sudo sed -i '/ens[0-9]\+/d' "$rt_tables_file"

# Add HTB root qdisc to all ens* interfaces
# Add route table name mapping at /etc/iproute2/rt_tables if not already present

table_id=200

for link in $links; do
    sudo tc qdisc add dev "$link" root handle 1: htb 2>/dev/null
    echo ""$table_id" "$link"" | sudo tee -a "$rt_tables_file" > /dev/null
    table_id=$((table_id + 1))
done

for link in $links; do
    gateway_ip=$(ip route show dev "$link" default | awk '{print $3}')
    while [ -z "$gateway_ip" ]; do
        sleep 1;
        gateway_ip=$(ip route show dev "$link" default | awk '{print $3}')
    done
    subnet_prefix=$(ip route show dev "$link" | grep "proto kernel" | awk '{print $1}')
    sudo ip route add default via "$gateway_ip" dev "$link" table "$link"
    sudo ip route add "$subnet_prefix" dev "$link" scope link table "$link"
done
