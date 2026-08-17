"""
sniffer.py
==========
Live packet capture and flow-level feature extraction engine.

Uses Scapy in promiscuous mode to intercept raw ingress packets.
Aggregates packets into flows using 5-tuple keys (src_ip, dst_ip,
src_port, dst_port, protocol) and sliding time windows.

Extracts 15-dimensional behavioral feature vectors per flow:
  [0]  src_ip_int         - Source IP as 32-bit integer
  [1]  dst_ip_int         - Destination IP as 32-bit integer
  [2]  src_port           - Source port (0-65535)
  [3]  dst_port           - Destination port (0-65535)
  [4]  protocol           - Protocol number (TCP=6, UDP=17, ICMP=1)
  [5]  pkt_count          - Total packet count in flow
  [6]  byte_count         - Total bytes in flow
  [7]  avg_pkt_len        - Mean packet size in bytes
  [8]  std_pkt_len        - Std deviation of packet sizes
  [9]  min_iat            - Minimum inter-arrival time (seconds)
  [10] max_iat            - Maximum inter-arrival time (seconds)
  [11] avg_iat            - Mean inter-arrival time (seconds)
  [12] flow_duration      - Total flow duration in seconds
  [13] syn_flag_ratio     - Ratio of SYN packets to total (TCP)
  [14] rst_flag_ratio     - Ratio of RST packets to total (TCP)

Designed for >= 50,000 concurrent flows with < 1ms extraction latency.
"""

import asyncio
import logging
import socket
import struct
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

import config

logger = logging.getLogger("firewall.sniffer")

# Type alias for the 5-tuple flow key
FlowKey = Tuple[str, str, int, int, int]


@dataclass
class FlowRecord:
    """
    Mutable state for a single active network flow.
    All timing uses monotonic clock for drift-free accuracy.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    pkt_count: int = 0
    byte_count: int = 0
    pkt_sizes: List[int] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)
    syn_count: int = 0
    rst_count: int = 0
    _prev_arrival: Optional[float] = field(default=None, repr=False)

    def update(self, pkt_size: int, is_syn: bool = False, is_rst: bool = False) -> None:
        """Update flow statistics with a new packet."""
        now = time.monotonic()

        # Inter-arrival time computation
        if self._prev_arrival is not None:
            iat = now - self._prev_arrival
            self.inter_arrival_times.append(iat)
        self._prev_arrival = now

        self.last_seen = now
        self.pkt_count += 1
        self.byte_count += pkt_size
        self.pkt_sizes.append(pkt_size)

        if is_syn:
            self.syn_count += 1
        if is_rst:
            self.rst_count += 1

    def to_feature_vector(self) -> np.ndarray:
        """
        Finalize the flow and return the 15-dimensional feature vector.
        Values are left unscaled; the ML pipeline handles normalization.
        """
        sizes = np.array(self.pkt_sizes, dtype=np.float32)
        iats = np.array(self.inter_arrival_times, dtype=np.float32)

        avg_pkt_len = float(np.mean(sizes)) if len(sizes) > 0 else 0.0
        std_pkt_len = float(np.std(sizes)) if len(sizes) > 1 else 0.0
        min_iat = float(np.min(iats)) if len(iats) > 0 else 0.0
        max_iat = float(np.max(iats)) if len(iats) > 0 else 0.0
        avg_iat = float(np.mean(iats)) if len(iats) > 0 else 0.0
        flow_duration = self.last_seen - self.start_time
        syn_ratio = self.syn_count / max(self.pkt_count, 1)
        rst_ratio = self.rst_count / max(self.pkt_count, 1)

        # Encode IPs as 32-bit integers for numerical processing
        try:
            src_ip_int = float(struct.unpack('!I', socket.inet_aton(self.src_ip))[0])
        except (OSError, struct.error):
            src_ip_int = 0.0
        try:
            dst_ip_int = float(struct.unpack('!I', socket.inet_aton(self.dst_ip))[0])
        except (OSError, struct.error):
            dst_ip_int = 0.0

        return np.array([
            src_ip_int, dst_ip_int,
            float(self.src_port), float(self.dst_port), float(self.protocol),
            float(self.pkt_count), float(self.byte_count),
            avg_pkt_len, std_pkt_len,
            min_iat, max_iat, avg_iat,
            float(flow_duration),
            float(syn_ratio), float(rst_ratio),
        ], dtype=np.float32)


class FlowTable:
    """
    Thread-safe hash table tracking up to max_flows concurrent flows.
    Uses a single RLock for simplicity; for ultra-high throughput (>100k flows/s),
    consider sharding into N sub-tables.
    """

    def __init__(self, max_flows: int = None, idle_timeout: float = None):
        self.max_flows = max_flows or config.MAX_CONCURRENT_FLOWS
        self.idle_timeout = idle_timeout or config.FLOW_IDLE_TIMEOUT
        self._table: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.RLock()
        self._evicted_count = 0

    def update_or_create(
        self, key: FlowKey, pkt_size: int,
        is_syn: bool = False, is_rst: bool = False,
    ) -> None:
        """Update an existing flow or create a new one."""
        with self._lock:
            if key in self._table:
                self._table[key].update(pkt_size, is_syn, is_rst)
            else:
                if len(self._table) >= self.max_flows:
                    self._evict_oldest()
                src_ip, dst_ip, src_port, dst_port, proto = key
                record = FlowRecord(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port, protocol=proto,
                )
                record.update(pkt_size, is_syn, is_rst)
                self._table[key] = record

    def collect_expired(self) -> List[Tuple[FlowKey, FlowRecord]]:
        """Atomically remove and return all idle-expired flows."""
        now = time.monotonic()
        expired = []
        with self._lock:
            expired_keys = [
                k for k, v in self._table.items()
                if (now - v.last_seen) >= self.idle_timeout
            ]
            for k in expired_keys:
                expired.append((k, self._table.pop(k)))
        return expired

    def collect_windowed(self, window_sec: float) -> List[Tuple[FlowKey, FlowRecord]]:
        """
        Return a snapshot of all flows that have been active within
        the last window_sec seconds, WITHOUT removing them.
        This is used for sliding-window feature extraction.
        """
        now = time.monotonic()
        active = []
        with self._lock:
            for k, v in self._table.items():
                if (now - v.last_seen) < window_sec and v.pkt_count >= 2:
                    active.append((k, v))
        return active

    def _evict_oldest(self) -> None:
        """Evict the flow with the oldest last_seen timestamp."""
        if not self._table:
            return
        oldest_key = min(self._table, key=lambda k: self._table[k].last_seen)
        del self._table[oldest_key]
        self._evicted_count += 1
        if self._evicted_count % 1000 == 0:
            logger.warning(
                "FlowTable evicted %d flows due to capacity pressure",
                self._evicted_count,
            )

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._table)


class PacketSniffer:
    """
    Main packet capture and feature extraction engine.

    Lifecycle:
        sniffer = PacketSniffer(feature_queue)
        await sniffer.start()
        # ... sniffer.feature_queue contains finalized feature dicts ...
        await sniffer.stop()
    """

    def __init__(self, feature_queue: Optional[asyncio.Queue] = None):
        self.interface = config.NETWORK_INTERFACE
        self.simulation_mode = config.SIMULATION_MODE
        self.feature_queue: asyncio.Queue = feature_queue or asyncio.Queue(
            maxsize=config.FEATURE_QUEUE_MAXSIZE
        )
        self.flow_table = FlowTable()

        self._sniffer = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._packets_captured = 0
        self._flows_finalized = 0

    async def start(self) -> None:
        """Start packet sniffing and flow expiry background tasks."""
        self._running = True
        self._loop = asyncio.get_running_loop()
        logger.info(
            "PacketSniffer starting on '%s' (simulation=%s)",
            self.interface, self.simulation_mode,
        )

        if self.simulation_mode:
            asyncio.create_task(self._simulation_producer())
        else:
            self._start_scapy_sniffer()

        asyncio.create_task(self._flow_expiry_loop())
        asyncio.create_task(self._window_extraction_loop())
        logger.info("PacketSniffer started successfully")

    async def stop(self) -> None:
        """Gracefully stop sniffing and flush remaining flows."""
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning("Error stopping sniffer: %s", e)
        logger.info(
            "PacketSniffer stopped. Packets: %d, Flows finalized: %d",
            self._packets_captured, self._flows_finalized,
        )

    # ------------------------------------------------------------------
    # Scapy sniffing
    # ------------------------------------------------------------------

    def _start_scapy_sniffer(self) -> None:
        """Launch Scapy's AsyncSniffer in a daemon thread."""
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                filter="ip",
            )
            self._sniffer.start()
            logger.info("Scapy AsyncSniffer launched on '%s'", self.interface)
        except ImportError:
            logger.error("Scapy not installed — falling back to simulation mode")
            self.simulation_mode = True
            asyncio.ensure_future(self._simulation_producer())
        except Exception as e:
            logger.error("Failed to start sniffer: %s. Falling back to simulation.", e)
            self.simulation_mode = True
            asyncio.ensure_future(self._simulation_producer())

    def _on_packet(self, pkt) -> None:
        """
        Scapy packet callback — runs in Scapy's sniffer thread.
        Must be fast; heavy work is deferred to background loops.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            pkt_size = len(pkt)
            is_syn = False
            is_rst = False

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                is_syn = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)
                is_rst = bool(tcp.flags & 0x04)
                proto = 6
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                proto = 17
            elif pkt.haslayer(ICMP):
                src_port = 0
                dst_port = 0
                proto = 1
            else:
                src_port = 0
                dst_port = 0

            flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port, proto)
            self.flow_table.update_or_create(flow_key, pkt_size, is_syn, is_rst)
            self._packets_captured += 1

            if self._packets_captured % 10000 == 0:
                logger.info(
                    "Captured %d pkts | Active flows: %d",
                    self._packets_captured, self.flow_table.active_count,
                )
        except Exception as e:
            logger.debug("Packet parse error: %s", e)

    # ------------------------------------------------------------------
    # Flow expiry and feature extraction loops
    # ------------------------------------------------------------------

    async def _flow_expiry_loop(self) -> None:
        """Periodically collect expired flows and extract features."""
        while self._running:
            await asyncio.sleep(config.FLOW_WINDOW_SHORT)
            try:
                expired = self.flow_table.collect_expired()
                for key, record in expired:
                    feature_vec = record.to_feature_vector()
                    flow_info = {
                        "features": feature_vec,
                        "src_ip": record.src_ip,
                        "dst_ip": record.dst_ip,
                        "flow_key": key,
                        "timestamp": time.time(),
                    }
                    try:
                        self.feature_queue.put_nowait(flow_info)
                        self._flows_finalized += 1
                    except asyncio.QueueFull:
                        logger.warning("Feature queue full — dropping flow")
            except Exception as e:
                logger.error("Flow expiry error: %s", e)

    async def _window_extraction_loop(self) -> None:
        """
        Sliding window extraction: Every FLOW_WINDOW_SHORT seconds,
        snapshot active flows and push their current feature vectors
        for real-time inference (even before they expire).
        """
        while self._running:
            await asyncio.sleep(config.FLOW_WINDOW_SHORT)
            try:
                active = self.flow_table.collect_windowed(config.FLOW_WINDOW_LONG)
                for key, record in active:
                    feature_vec = record.to_feature_vector()
                    flow_info = {
                        "features": feature_vec,
                        "src_ip": record.src_ip,
                        "dst_ip": record.dst_ip,
                        "flow_key": key,
                        "timestamp": time.time(),
                    }
                    try:
                        self.feature_queue.put_nowait(flow_info)
                    except asyncio.QueueFull:
                        pass  # Non-critical — window snapshots are supplemental
            except Exception as e:
                logger.error("Window extraction error: %s", e)

    # ------------------------------------------------------------------
    # Simulation mode
    # ------------------------------------------------------------------

    async def _simulation_producer(self) -> None:
        """
        Generate synthetic traffic for testing on Windows/macOS.
        Produces a mix of normal and attack-like flows.
        """
        logger.info("Simulation mode: generating synthetic traffic")
        rng = np.random.default_rng(42)
        attack_types = ["normal", "syn_flood", "port_scan", "udp_burst"]
        attack_weights = [0.7, 0.1, 0.1, 0.1]

        while self._running:
            await asyncio.sleep(0.05)  # ~20 flows/second

            attack = rng.choice(attack_types, p=attack_weights)

            if attack == "normal":
                src_ip = f"192.168.1.{rng.integers(1, 254)}"
                dst_ip = f"10.0.0.{rng.integers(1, 254)}"
                src_port = int(rng.integers(1024, 65535))
                dst_port = int(rng.choice([80, 443, 8080, 22, 53]))
                proto = int(rng.choice([6, 17]))
                pkt_count = int(rng.integers(5, 50))
                syn_ratio = rng.uniform(0.0, 0.15)
                rst_ratio = rng.uniform(0.0, 0.05)
            elif attack == "syn_flood":
                src_ip = f"{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}"
                dst_ip = "10.0.0.1"
                src_port = int(rng.integers(1024, 65535))
                dst_port = 80
                proto = 6
                pkt_count = int(rng.integers(500, 5000))
                syn_ratio = rng.uniform(0.85, 1.0)
                rst_ratio = rng.uniform(0.0, 0.02)
            elif attack == "port_scan":
                src_ip = f"{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}"
                dst_ip = "10.0.0.1"
                src_port = int(rng.integers(1024, 65535))
                dst_port = int(rng.integers(1, 1024))
                proto = 6
                pkt_count = int(rng.integers(1, 5))
                syn_ratio = rng.uniform(0.8, 1.0)
                rst_ratio = rng.uniform(0.3, 0.8)
            else:  # udp_burst
                src_ip = f"{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)}"
                dst_ip = "10.0.0.1"
                src_port = int(rng.integers(1024, 65535))
                dst_port = int(rng.integers(1, 65535))
                proto = 17
                pkt_count = int(rng.integers(1000, 10000))
                syn_ratio = 0.0
                rst_ratio = 0.0

            # Build synthetic feature vector
            try:
                src_ip_int = float(struct.unpack('!I', socket.inet_aton(src_ip))[0])
            except (OSError, struct.error):
                src_ip_int = 0.0
            try:
                dst_ip_int = float(struct.unpack('!I', socket.inet_aton(dst_ip))[0])
            except (OSError, struct.error):
                dst_ip_int = 0.0

            byte_count = pkt_count * int(rng.integers(40, 1500))
            avg_pkt_len = byte_count / max(pkt_count, 1)
            std_pkt_len = float(rng.uniform(10, 500))
            flow_duration = float(rng.uniform(0.01, 10.0))
            avg_iat = flow_duration / max(pkt_count - 1, 1)
            min_iat = avg_iat * 0.1
            max_iat = avg_iat * 3.0

            features = np.array([
                src_ip_int, dst_ip_int,
                float(src_port), float(dst_port), float(proto),
                float(pkt_count), float(byte_count),
                avg_pkt_len, std_pkt_len,
                min_iat, max_iat, avg_iat,
                flow_duration,
                float(syn_ratio), float(rst_ratio),
            ], dtype=np.float32)

            flow_info = {
                "features": features,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "flow_key": (src_ip, dst_ip, src_port, dst_port, proto),
                "timestamp": time.time(),
            }
            try:
                self.feature_queue.put_nowait(flow_info)
                self._flows_finalized += 1
            except asyncio.QueueFull:
                pass

            self._packets_captured += pkt_count
