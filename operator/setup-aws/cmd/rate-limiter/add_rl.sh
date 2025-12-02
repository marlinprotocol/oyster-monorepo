#!/bin/bash


# Usage: add_rl.sh <sec_ip> <private_ip> <device_mac> <bandwidth> <instance_bandwidth>
# Adds nft rules, ip rule, tc filters/classes to limit bandwidth
# Also updates bandwidth usage tracking
# Arguments:
#   sec_ip: The secondary IP address of Rate Limit VM
#   private_ip: The private IP address of the CVM instance
#   device_mac: The MAC address of the network device
#   bandwidth: The bandwidth limit to set (in bits/sec)
#   instance_bandwidth: The total bandwidth limit for the instance (in bits/sec)

# Check if all 5 arguments are provided
if [ $# -ne 5 ]; then
    echo "Usage: $0 <sec_ip> <private_ip> <device_mac> <bandwidth> <instance_bandwidth>"
    exit 1
fi

source "$(dirname "$0")/common_rl.sh"

SEC_IP="$1"
PRIVATE_IP="$2"
DEVICE_MAC="$3"
BANDWIDTH="$4"
INSTANCE_BANDWIDTH="$5"

check_and_update_bandwidth() {
    local bandwidth="$1"
    local instance_bandwidth="$2"
    local bandwidth_usage_file="/var/run/bandwidth_usage.txt"
    local lock_file="/var/lock/rate_limiter.lock"
    
    local lock_fd
    exec {lock_fd}> "$lock_file" || return 1 
    flock -x "$lock_fd" || return 1

    if [ ! -f "$bandwidth_usage_file" ]; then
        sudo touch "$bandwidth_usage_file"
        echo "0" | sudo tee "$bandwidth_usage_file" > /dev/null
        sudo chmod 644 "$bandwidth_usage_file"
    fi

    local current_usage
    current_usage=$(cat "$bandwidth_usage_file" 2>/dev/null)
    local new_usage=$((current_usage + bandwidth))

    if [ "$new_usage" -gt "$instance_bandwidth" ]; then
        echo "Cannot allocate $bandwidth bps. Current usage: $current_usage bps, Instance limit: $instance_bandwidth bps" >&2
        exec {lock_fd}>&-
        return 1
    fi

    echo "$new_usage" | sudo tee "$bandwidth_usage_file" > /dev/null
    exec {lock_fd}>&-
    return 0
}


add_nft_rules() {
    local private_ip="$1"
    local sec_ip="$2"
    sudo nft add rule ip raw postrouting ip saddr "$private_ip" notrack ip saddr set "$sec_ip"

    if [ $? -ne 0 ]; then
        echo "Failed to add nft rule for source address" >&2
        return 1
    fi

    sudo nft add rule ip raw prerouting ip daddr "$sec_ip" notrack ip daddr set "$private_ip"

    if [ $? -ne 0 ]; then
        echo "Failed to add nft rule for destination address" >&2
        
        # Rollback the previously added SNAT rule
        rule="ip saddr $private_ip notrack ip saddr set $sec_ip"
        handle=$(sudo nft -a list chain ip raw postrouting 2>/dev/null | grep "$rule" | awk '{print $NF}')
        
        if [ -n "$handle" ]; then
            sudo nft delete rule ip raw postrouting handle "$handle"
        fi
        return 1
    fi
}


add_ip_rule() {
    local private_ip="$1"
    local device_mac="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        echo "Device for MAC $device_mac not found" >&2
        return 1
    fi
    sudo ip rule add from "$private_ip" table "$dev"

    if [ $? -ne 0 ]; then
        echo "Failed to add ip rule from $private_ip to table $dev" >&2
        return 1
    fi
}

add_tc_rules() {
    local device_mac="$1"
    local sec_ip="$2"
    local bandwidth="$3"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        echo "Device for MAC $device_mac not found" >&2
        return 1
    fi

    # Ensure HTB root qdisc with handle 1: exists
    if ! tc qdisc show dev "$dev" | grep -q 'htb 1: root'; then
        sudo tc qdisc add dev "$dev" root handle 1: htb
    fi

    # Try adding a random class id directly; on failure retry to avoid races
    local class_id
    local attempt max_attempts=1000
    for attempt in $(seq 1 $max_attempts); do
        # combine RANDOMs to get a wider range, ensure between 10 and 65535
        class_id=$(( (RANDOM % 65535) + 1 ))
        if sudo tc class add dev "$dev" parent 1: classid 1:"$class_id" htb rate "$bandwidth" burst 4000m 2>/dev/null; then
            break
        fi
    done

    if [ -z "$class_id" ]; then
        echo "Failed to add tc class after $max_attempts attempts" >&2
        return 1
    fi

    # Add filter matching source IP to this class if not present
    sudo tc filter add dev "$dev" protocol ip parent 1:0 prio 1 u32 match ip src "$sec_ip" flowid 1:"$class_id"
    if [ $? -ne 0 ]; then
        echo "Failed to add tc filter for source IP $sec_ip" >&2
        # Rollback class addition
        sudo tc class del dev "$dev" parent 1: classid 1:"$class_id"
        return 1
    fi
}

check_and_update_bandwidth "$BANDWIDTH" "$INSTANCE_BANDWIDTH"

if [ $? -ne 0 ]; then
    exit 1
fi

add_nft_rules "$PRIVATE_IP" "$SEC_IP"
if [ $? -ne 0 ]; then
    free_bandwidth_usage "$BANDWIDTH"
    exit 1
fi

add_ip_rule "$PRIVATE_IP" "$DEVICE_MAC"
if [ $? -ne 0 ]; then
    remove_nft_rules "$PRIVATE_IP" "$SEC_IP"
    free_bandwidth_usage "$BANDWIDTH"
    exit 1
fi

add_tc_rules "$DEVICE_MAC" "$SEC_IP" "$BANDWIDTH"
if [ $? -ne 0 ]; then
    remove_ip_rule "$PRIVATE_IP" "$DEVICE_MAC"
    remove_nft_rules "$PRIVATE_IP" "$SEC_IP"
    free_bandwidth_usage "$BANDWIDTH"
    exit 1
fi
