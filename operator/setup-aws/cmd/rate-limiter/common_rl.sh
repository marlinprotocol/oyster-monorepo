#!/bin/bash

get_dev_name() {
    local device_mac="$1"
    ip -o link show | grep "$device_mac" | awk -F': ' '{print $2}'
}

remove_nft_rules() {
    local private_ip="$1"
    local sec_ip="$2"

    # Find rule handles in ip raw prerouting that reference both IPs and delete them
    rule="ip saddr $private_ip notrack ip saddr set $sec_ip"
    handle=$(sudo nft -a list chain ip raw postrouting 2>/dev/null | grep "$rule" | awk '{print $NF}')
    if [ -n "$handle" ]; then
        sudo nft delete rule ip raw postrouting handle "$handle"
    fi

    rule="ip daddr $sec_ip notrack ip daddr set $private_ip"
    handle=$(sudo nft -a list chain ip raw prerouting 2>/dev/null | grep "$rule" | awk '{print $NF}')
    if [ -n "$handle" ]; then
        sudo nft delete rule ip raw prerouting handle "$handle"
    fi
}

remove_ip_rule() {
    local private_ip="$1"
    local device_mac="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        return 0
    fi

    # Remove matching ip rule (ignore errors if not present)
    sudo ip rule del from "$private_ip" table "$dev"
}

free_bandwidth_usage() {
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
