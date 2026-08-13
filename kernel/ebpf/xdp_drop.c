// kernel/ebpf/xdp_drop.c
/*
 * High-performance XDP (eXpress Data Path) packet dropping program.
 *
 * This eBPF program runs at the earliest possible point in the Linux kernel
 * networking stack, before the sk_buff allocation. It performs O(1) lookups
 * against a BPF map of blacklisted IPs.
 *
 * It is dynamically compiled and loaded by bcc in Python.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>

// BPF Map definition: Hash map containing malicious source IPs
// Key: u32 (IPv4 address), Value: u64 (hit counter)
BPF_HASH(drop_ips, u32, u64, 100000);

// Global metrics map for total packets dropped by XDP
BPF_ARRAY(metrics, u64, 1);

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Only inspect IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;

    // Lookup IP in the blacklist map
    u64 *val = drop_ips.lookup(&src_ip);
    if (val) {
        // Increment the per-IP hit counter
        lock_xadd(val, 1);

        // Increment the global drop counter
        u32 metrics_key = 0;
        u64 *global_metric = metrics.lookup(&metrics_key);
        if (global_metric) {
            lock_xadd(global_metric, 1);
        }

        // Drop the packet directly at the NIC driver level
        return XDP_DROP;
    }

    // IP not blacklisted, pass up the stack to nftables / user-space
    return XDP_PASS;
}
