"""
ebpf_core.py
============
eBPF / XDP (eXpress Data Path) Kernel Mitigation Module.

This represents the 'Ultimate Tier' of network security. Instead of using 
standard iptables/nftables which process packets in the OS network stack,
XDP attaches a compiled C program directly to the Network Interface Card (NIC) driver.
This allows the firewall to drop malicious packets at wire-speed (10M+ packets/sec)
before the CPU even processes them.
"""

import logging
import platform

logger = logging.getLogger(__name__)

XDP_C_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(drop_list, u32, u64);

int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    u32 src_ip = ip->saddr;
    u64 *value = drop_list.lookup(&src_ip);
    
    if (value) {
        // Wire-speed drop at the NIC level
        return XDP_DROP;
    }
    
    return XDP_PASS;
}
"""

class eBPFEnforcer:
    def __init__(self, interface: str = "eth0", simulation_mode: bool = False):
        self.interface = interface
        self.simulation_mode = simulation_mode
        self.bpf = None
        self.drop_list = None
        
        if not self.simulation_mode and platform.system() == "Linux":
            self._compile_and_attach()
        else:
            logger.warning("eBPF Enforcer running in DRY-RUN/Simulation mode (Windows/Mac).")

    def _compile_and_attach(self):
        try:
            from bcc import BPF
            logger.info("Compiling eBPF/XDP C program...")
            self.bpf = BPF(text=XDP_C_PROGRAM)
            fn = self.bpf.load_func("xdp_firewall", BPF.XDP)
            self.bpf.attach_xdp(self.interface, fn, 0)
            self.drop_list = self.bpf.get_table("drop_list")
            logger.info(f"eBPF XDP program successfully attached to {self.interface}!")
        except Exception as e:
            logger.error(f"Failed to load eBPF (requires root and bcc): {e}")

    def block_ip(self, ip_int: int):
        if self.simulation_mode:
            logger.debug(f"[eBPF SIMULATION] Wire-speed drop engaged for IP int: {ip_int}")
            return
        if self.drop_list is not None:
            import ctypes
            self.drop_list[ctypes.c_uint(ip_int)] = ctypes.c_ulong(1)
            logger.info(f"[eBPF] IP {ip_int} added to XDP NIC drop map.")
