"""
kernel/ebpf/loader.py
======================
Python loader and manager for the XDP eBPF firewall program.

This module uses the BCC (BPF Compiler Collection) framework to compile
and attach the XDP program to a network interface.
"""

import logging
import socket
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)

class XdpManager:
    def __init__(self, interface: str, c_source_path: str = "kernel/ebpf/xdp_drop.c"):
        self.interface = interface
        self.c_source_path = c_source_path
        self.bpf = None
        self._enabled = False

    def load_and_attach(self) -> bool:
        """Compile and attach the XDP program."""
        try:
            from bcc import BPF
        except ImportError:
            logger.error("BCC library not installed. eBPF/XDP requires linux-headers and bcc-python.")
            return False

        try:
            logger.info("Loading XDP program from %s onto %s...", self.c_source_path, self.interface)
            with open(self.c_source_path, "r") as f:
                c_text = f.read()

            self.bpf = BPF(text=c_text)
            fn = self.bpf.load_func("xdp_firewall", BPF.XDP)
            
            # Attach XDP program
            self.bpf.attach_xdp(self.interface, fn, 0)
            self._enabled = True
            logger.info("XDP program successfully attached to %s", self.interface)
            return True
        except Exception as e:
            logger.error("Failed to load/attach XDP program: %s", e)
            return False

    def detach(self) -> None:
        """Detach the XDP program from the interface."""
        if self._enabled and self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                logger.info("XDP program detached from %s", self.interface)
            except Exception as e:
                logger.error("Failed to detach XDP program: %s", e)
            finally:
                self._enabled = False

    def block_ip(self, ip_str: str) -> bool:
        """Add an IP to the XDP blocklist."""
        if not self._enabled or not self.bpf:
            return False
        
        try:
            ip_int = struct.unpack("I", socket.inet_aton(ip_str))[0]
            drop_ips = self.bpf.get_table("drop_ips")
            key = drop_ips.Key(ip_int)
            val = drop_ips.Leaf(0)  # Initial hit count = 0
            drop_ips[key] = val
            logger.debug("IP %s added to XDP blocklist", ip_str)
            return True
        except Exception as e:
            logger.error("Failed to block IP %s via XDP: %s", ip_str, e)
            return False

    def unblock_ip(self, ip_str: str) -> bool:
        """Remove an IP from the XDP blocklist."""
        if not self._enabled or not self.bpf:
            return False
            
        try:
            ip_int = struct.unpack("I", socket.inet_aton(ip_str))[0]
            drop_ips = self.bpf.get_table("drop_ips")
            key = drop_ips.Key(ip_int)
            del drop_ips[key]
            logger.debug("IP %s removed from XDP blocklist", ip_str)
            return True
        except KeyError:
            pass # IP wasn't in the map
        except Exception as e:
            logger.error("Failed to unblock IP %s via XDP: %s", ip_str, e)
            return False
        return True

    def get_stats(self) -> dict:
        """Read metrics from the XDP maps."""
        if not self._enabled or not self.bpf:
            return {"enabled": False}
            
        try:
            metrics = self.bpf.get_table("metrics")
            key = metrics.Key(0)
            total_dropped = metrics[key].value if key in metrics else 0
            
            drop_ips = self.bpf.get_table("drop_ips")
            num_blocked_ips = len(drop_ips)
            
            return {
                "enabled": True,
                "interface": self.interface,
                "total_dropped": total_dropped,
                "blocked_ips_count": num_blocked_ips
            }
        except Exception as e:
            logger.error("Failed to read XDP stats: %s", e)
            return {"enabled": True, "error": str(e)}
