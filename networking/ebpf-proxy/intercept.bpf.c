// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>

#include <bpf/bpf_endian.h> // For bpf_ntohs
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h> // struct ethhdr, ETH_P_IP
#include <linux/ip.h>       // struct iphdr
#include <linux/pkt_cls.h>  // TC_ACT_OK

// --- Constants ---
// Max packet data to capture and send to userspace (adjust as needed)
#define MAX_PKT_SIZE 1500 // Typical MTU

// --- Data Structure for Perf Event ---
// This struct will be sent to userspace via the perf buffer.
struct pkt_event {
  __u32 pkt_len;               // Original packet length
  __u8 pkt_data[MAX_PKT_SIZE]; // Captured packet data
};
// Force emitting struct pkt_event into the ELF.
const struct pkt_event *unused __attribute__((unused));

// --- Perf Buffer Map ---
// Map to send packet data to userspace.
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  // TODO: figure out how to right size this
  __uint(max_entries, 1024); // Should be >= number of CPUs
} perf_output SEC(".maps");

// --- Per-CPU Temporary Buffer Map ---
// Map to construct the singular pkt_event, too big to put on stack
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));              // Key is just 0
  __uint(value_size, sizeof(struct pkt_event)); // Value holds our data
  __uint(max_entries, 1);                       // Only one entry needed
} pkt_event_buffer SEC(".maps");

// --- TC Egress Program ---
SEC("tc/egress")
int capture_egress_packets(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth;
  __u32 zero = 0; // blergh
  // Load pointer to temporary packet
  struct pkt_event *event = bpf_map_lookup_elem(&pkt_event_buffer, &zero);
  if (!event) {
    return TC_ACT_SHOT; // Init issue? drop
  }

  // Check if packets are too big
  if (skb->len > MAX_PKT_SIZE + sizeof(struct ethhdr)) {
    return TC_ACT_SHOT; // Too much data, drop
  }

  // Check we have at least IP header
  // before casting and dereferencing
  // technically need only ethernet, future proofed
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    return TC_ACT_SHOT; // Not enough data, drop
  }

  eth = (struct ethhdr *)data;

  // Filter for IPv4 packets (EtherType 0x0800)
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return TC_ACT_SHOT; // Not IPv4, drop
  }

  // Check if packet is too small
  // Not needed, verifier wants it for the subtraction
  // Equality needed to make it non zero for the load
  if (skb->len <= sizeof(struct ethhdr)) {
    return TC_ACT_SHOT; // Too small, drop
  }

  // Prepare data for userspace
  event->pkt_len = skb->len - sizeof(struct ethhdr); // Store length

  // Copy packet data into the event struct, after ethernet header
  // bpf_skb_load_bytes is safer than direct pointer access for larger reads
  int ret = bpf_skb_load_bytes(skb, sizeof(struct ethhdr), event->pkt_data,
                               event->pkt_len);
  if (ret < 0) {
    // Failed to load bytes, can this happen? Drop.
    return TC_ACT_SHOT;
  }

  // Send data to userspace via perf buffer
  // Use BPF_F_CURRENT_CPU as the flag for perf_event_output.
  // The first argument (skb) is the context.
  // The second argument is the map descriptor.
  // The third is the index (flags), usually BPF_F_CURRENT_CPU.
  // The fourth is the data pointer.
  // The fifth is the size of the data.
  // Ignore return value since we are dropping anyway
  bpf_perf_event_output(skb, &perf_output, BPF_F_CURRENT_CPU, event,
                        sizeof(*event));

  // No point continuing, just drop
  return TC_ACT_SHOT;
}

// --- License ---
// Required for eBPF programs.
char LICENSE[] SEC("license") = "GPL";
