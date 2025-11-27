#!/bin/bash

# Usage: remove_rl.sh <sec_ip> <private_ip> <device_mac> <bandwidth>
# Removes nft rules, ip rule, tc filters/classes created by add_rl.sh
# Also updates bandwidth usage tracking
# Arguments:
#   sec_ip: The secondary IP address of Rate Limit VM
#   private_ip: The private IP address of the CVM instance
#   device_mac: The MAC address of the network device
#   bandwidth: The bandwidth limit to set (in bits/sec)
# [TODO] set -euo pipefail


if [ $# -ne 4 ]; then
    echo "Usage: $0 <sec_ip> <private_ip> <device_mac> <bandwidth>"
    exit 1
fi

SEC_IP="$1"
PRIVATE_IP="$2"
DEVICE_MAC="$3"
BANDWIDTH="$4"

source "$(dirname "$0")/common_rl.sh"

remove_tc_rules() {
    local device_mac="$1"
    local sec_ip="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        return 0
    fi
    # Convert sec_ip to hex decimal string for filter handle
    sec_ip_hex=$(echo "$sec_ip" | awk -F. '{printf "%02x%02x%02x%02x\n", $1, $2, $3, $4}')

    filter=$(sudo tc filter show dev "$dev" parent 1: 2>/dev/null | grep -B1 "$sec_ip_hex" | head -n1)
    if [ -z "$filter" ]; then
        return 0
    fi

    filter_handle=$(echo "$filter" | awk -F'fh ' '{print $2}' | awk '{print $1}')
    classid=$(echo "$filter" | awk -F'flowid ' '{print $2}' | awk '{print $1}')

    sudo tc filter del dev "$dev" parent 1: protocol ip pref 1 handle "$filter_handle" u32
    sudo tc class del dev "$dev" parent 1: classid "$classid"

}


# Run removals in safe order (filters/classes -> ip rule -> nft)
remove_tc_rules "$DEVICE_MAC" "$SEC_IP"
remove_ip_rule "$PRIVATE_IP" "$DEVICE_MAC"
remove_nft_rules "$PRIVATE_IP" "$SEC_IP"
free_bandwidth_usage "$BANDWIDTH"
