#!/bin/bash

# Usage: remove_rl.sh <sec_ip> <private_ip> <device_mac> <bandwidth>
# Removes nft rules, ip rule, tc filters/classes created by add_rl.sh
# Also updates bandwidth usage tracking
# Arguments:
#   job_id: The unique identifier for the rate limiting job
#   sec_ip: The secondary IP address of Rate Limit VM
#   private_ip: The private IP address of the CVM instance
#   device_mac: The MAC address of the network device
#   bandwidth: The bandwidth limit to set (in bits/sec)

if [ $# -ne 5 ]; then
    echo "Usage: $0 <job_id> <sec_ip> <private_ip> <device_mac> <bandwidth>"
    exit 1
fi

JOB_ID="$1"
SEC_IP="$2"
PRIVATE_IP="$3"
DEVICE_MAC="$4"
BANDWIDTH="$5"

source "$(dirname "$0")/common_rl.sh"

# Run removals in safe order (filters/classes -> ip rule -> nft)
job_exists "$JOB_ID"
if [ $? -ne 0 ]; then
    exit 0
fi
remove_job "$JOB_ID"
remove_tc_rules "$DEVICE_MAC" "$SEC_IP"
remove_ip_rule "$PRIVATE_IP" "$DEVICE_MAC"
remove_nft_rules "$PRIVATE_IP" "$SEC_IP"
free_bandwidth_usage "$BANDWIDTH"
