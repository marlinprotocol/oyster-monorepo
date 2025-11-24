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

get_dev_name() {
    local device_mac="$1"
    ip -o link show | grep -i "$device_mac" | awk -F': ' '{print $2}'
}

remove_nft_rules() {
    local private_ip="$1"
    local sec_ip="$2"

    # Find rule handles in ip raw prerouting that reference both IPs and delete them
    rule="ip saddr $private_ip notrack ip saddr set $sec_ip"
    handle=$(sudo nft -a list chain ip raw prerouting 2>/dev/null | grep "$rule" | awk '{print $NF}')
    if [ -n "$handle" ]; then
        sudo nft delete rule ip raw prerouting handle "$handle"
    fi

    rule="ip daddr $sec_ip notrack ip daddr set $private_ip"
    handle=$(sudo nft -a list chain ip raw prerouting 2>/dev/null | grep "$rule" | awk '{print $NF}')
    if [ -n "$handle" ]; then
        sudo nft delete rule ip raw prerouting handle "$handle"
    fi
}

remove_ip_rule() {
    local sec_ip="$1"
    local device_mac="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        return 0
    fi

    # Remove matching ip rule (ignore errors if not present)
    sudo ip rule del from "$sec_ip" table "$dev" 2>/dev/null || true
}

remove_tc_rules() {
    local device_mac="$1"
    local sec_ip="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        return 0
    fi
    # TODO: get exact filter handle and classid instead of hardcoding from show output
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

update_bandwidth_usage() {
    local bandwidth="$1"
    local lock_file="/var/lock/rate_limiter.lock"
    local usage_file="/var/run/bandwidth_usage.txt"

    local lock_fd
    exec {lock_fd}> "$lock_file" || return 1
    flock -x "$lock_fd" || return 1

    local current_usage
    current_usage=$(cat "$usage_file" 2>/dev/null)

    local new_usage=$((current_usage - bandwidth))
    [ "$new_usage" -lt 0 ] && new_usage=0

    echo "$new_usage" | sudo tee "$usage_file" > /dev/null

    exec {lock_fd}>&-
}

# Run removals in safe order (filters/classes -> ip rule -> nft)
remove_tc_rules "$DEVICE_MAC" "$SEC_IP"
remove_ip_rule "$SEC_IP" "$DEVICE_MAC"
remove_nft_rules "$PRIVATE_IP" "$SEC_IP"
update_bandwidth_usage "$BANDWIDTH"
