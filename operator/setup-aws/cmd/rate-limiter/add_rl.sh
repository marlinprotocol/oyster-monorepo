#!/bin/bash

# Check if all 4 arguments are provided
if [ $# -ne 4 ]; then
    echo "Usage: $0 <sec_ip> <private_ip> <device_mac> <bandwidth>"
    exit 1
fi

SEC_IP="$1"
PRIVATE_IP="$2"
DEVICE_MAC="$3"
BANDWIDTH="$4"

echo "Security IP: $SEC_IP"
echo "Private IP: $PRIVATE_IP"
echo "Device MAC: $DEVICE_MAC"
echo "Bandwidth: $BANDWIDTH"

add_nft_rules() {
    local private_ip="$1"
    local sec_ip="$2"
    
    sudo nft add rule ip raw prerouting ip saddr "$private_ip" notrack ip saddr set "$sec_ip"
    sudo nft add rule ip raw prerouting ip daddr "$sec_ip" notrack ip daddr set "$private_ip"
}

get_dev_name() {
    local device_mac="$1"
    ip -o link show | grep "$device_mac" | awk -F': ' '{print $2}'
}

add_ip_rule() {
    local sec_ip="$1"
    local device_mac="$2"

    local dev
    dev=$(get_dev_name "$device_mac")

    if [ -z "$dev" ]; then
        echo "Device for MAC $device_mac not found" >&2
        return 1
    fi

    # Avoid adding duplicate rule
    if ip rule show | grep -qE "from[[:space:]]+$sec_ip.*(lookup|table)[[:space:]]+$dev"; then
        return 0
    fi

    sudo ip rule add from "$sec_ip" table "$dev"
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
        if sudo tc class add dev "$dev" parent 1: classid 1:"$class_id" htb rate "$bandwidth" burst 15k 2>/dev/null; then
            break
        fi
    done

    if [ -z "$class_id" ]; then
        echo "Failed to add tc class after $max_attempts attempts" >&2
        return 1
    fi

    # Add filter matching source IP to this class if not present
    if ! tc filter show dev "$dev" parent 1:0 | grep -q "$sec_ip"; then
        sudo tc filter add dev "$dev" protocol ip parent 1:0 prio 1 u32 match ip src "$sec_ip" flowid 1:"$class_id"
    fi
}

# TODO: rollback or cleanup if any step fails

add_nft_rules "$PRIVATE_IP" "$SEC_IP"

add_ip_rule "$SEC_IP" "$DEVICE_MAC"

add_tc_rules "$DEVICE_MAC" "$SEC_IP" "$BANDWIDTH"
