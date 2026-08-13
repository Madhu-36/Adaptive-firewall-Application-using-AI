"""
sniffer/packet_engine.py
========================
Live packet capture engine using Scapy in promiscuous mode.

Key responsibilities:
  1. Capture raw IP packets from a network interface (AsyncSniffer).
  2. Maintain a thread-safe FlowTable tracking per-5-tuple flow state.
  3. Compute 14-dimensional feature vectors per flow when flows expire.
  4. Push finalized feature vectors to an asyncio.Queue for ML consumption.

Feature Vector (14 dimensions):
  [0]  src_ip_int       - Source IP as 32-bit integer (normalized)
  [1]  dst_ip_int       - Destination IP as 32-bit integer (normalized)
  [2]  src_port         - Source port (0-65535, normalized)
  [3]  dst_port         - Destination port (0-65535, normalized)
  [4]  protocol         - Protocol number (TCP=6, UDP=17, ICMP=1, other=0)
  [5]  pkt_count        - Total packet count in flow
  [6]  byte_count       - Total bytes in flow
  [7]  avg_pkt_size     - Mean packet size in bytes
  [8]  std_pkt_size     - Std deviation of packet sizes
  [9]  min_iat          - Minimum inter-arrival time (seconds)
  [10] max_iat          - Maximum inter-arrival time (seconds)
  [11] avg_iat          - Mean inter-arrival time (seconds)
  [12] flow_duration    - Total flow duration in seconds
  [13] syn_flag_ratio   - Ratio of SYN packets to total (TCP only)

Target: >= 50,000 concurrent flows, < 1ms feature extraction per flow.
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
import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias for the 5-tuple flow key
# (src_ip, dst_ip, src_port, dst_port, protocol)
# ---------------------------------------------------------------------------
FlowKey = Tuple[str, str, int, int, int]


@dataclass
class FlowRecord:
    """
    Mutable state for a single active network flow.
    All timing uses monotonic clock for accuracy.
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
    _prev_arrival: Optional[float] = field(default=None, repr=False)

    def update(self, pkt_size: int, is_syn: bool = False) -> None:
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

    def to_feature_vector(self) -> np.ndarray:
        """
        Finalize the flow and return the 14-dimensional feature vector.
        All values are left unscaled — the ML model's StandardScaler handles normalization.
        """
        sizes = np.array(self.pkt_sizes, dtype=np.float32)
        iats = np.array(self.inter_arrival_times, dtype=np.float32)

        avg_pkt_size = float(np.mean(sizes)) if len(sizes) > 0 else 0.0
        std_pkt_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0
        min_iat = float(np.min(iats)) if len(iats) > 0 else 0.0
        max_iat = float(np.max(iats)) if len(iats) > 0 else 0.0
        avg_iat = float(np.mean(iats)) if len(iats) > 0 else 0.0
        flow_duration = self.last_seen - self.start_time
        syn_ratio = self.syn_count / self.pkt_count if self.pkt_count > 0 else 0.0

        # Encode IPs as 32-bit integers for numerical processing
        try:
            src_ip_int = float(struct.unpack('!I', socket.inet_aton(self.src_ip))[0])
        except Exception:
            src_ip_int = 0.0
        try:
            dst_ip_int = float(struct.unpack('!I', socket.inet_aton(self.dst_ip))[0])
        except Exception:
            dst_ip_int = 0.0

        return np.array([
            src_ip_int,
            dst_ip_int,
            float(self.src_port),
            float(self.dst_port),
            float(self.protocol),
            float(self.pkt_count),
            float(self.byte_count),
            avg_pkt_size,
            std_pkt_size,
            min_iat,
            max_iat,
            avg_iat,
            float(flow_duration),
            float(syn_ratio),
        ], dtype=np.float32)


class FlowTable:
    """
    Thread-safe hash table tracking up to `max_flows` concurrent network flows.

    Uses a single RLock to allow nested locking during cleanup. For very high
    throughput (> 100k flows/s), consider sharding into N sub-tables each with
    its own lock.
    """

    def __init__(self, max_flows: int = 50_000, idle_timeout: float = 60.0):
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self._table: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.RLock()
        self._evicted_count = 0

    def update_or_create(self, key: FlowKey, pkt_size: int, is_syn: bool = False) -> None:
        """Update an existing flow or create a new one. Drops new flows if table is full."""
        with self._lock:
            if key in self._table:
                self._table[key].update(pkt_size, is_syn)
            else:
                if len(self._table) >= self.max_flows:
                    # Table full — evict oldest flow to make space
                    self._evict_oldest()
                src_ip, dst_ip, src_port, dst_port, proto = key
                record = FlowRecord(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port, protocol=proto
                )
                record.update(pkt_size, is_syn)
                self._table[key] = record

    def collect_expired(self) -> List[Tuple[FlowKey, FlowRecord]]:
        """
        Atomically remove and return all flows that have been idle
        longer than `idle_timeout` seconds.
        """
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

    def _evict_oldest(self) -> None:
        """Evict the flow with the oldest last_seen timestamp (called while holding lock)."""
        if not self._table:
            return
        oldest_key = min(self._table, key=lambda k: self._table[k].last_seen)
        del self._table[oldest_key]
        self._evicted_count += 1
        if self._evicted_count % 1000 == 0:
            logger.warning("FlowTable evicted %d flows due to capacity pressure", self._evicted_count)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._table)


class PacketEngine:
    """
    Main packet capture and feature extraction engine.

    Usage:
        engine = PacketEngine(config)
        await engine.start()   # begins sniffing and flow expiry loop
        # engine.feature_queue contains finalized FlowRecord feature vectors
        await engine.stop()
    """

    def __init__(self, config: dict, feature_queue: Optional[asyncio.Queue] = None):
        self.config = config
        self.interface = config.get("firewall", {}).get("interface", "eth0")
        self.simulation_mode = config.get("firewall", {}).get("simulation_mode", False)
        self.idle_timeout = config.get("flow", {}).get("idle_timeout_sec", 60)
        self.max_flows = config.get("flow", {}).get("max_concurrent_flows", 50_000)
        queue_maxsize = config.get("flow", {}).get("feature_queue_maxsize", 10_000)

        self.feature_queue: asyncio.Queue = feature_queue or asyncio.Queue(maxsize=queue_maxsize)
        self.flow_table = FlowTable(max_flows=self.max_flows, idle_timeout=self.idle_timeout)

        self._sniffer = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._packets_captured = 0
        self._flows_finalized = 0

    # ------------------------------------------------------------------
    # Public lifecycle methods
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start packet sniffing and flow expiry background tasks."""
        self._running = True
        self._loop = asyncio.get_running_loop()
        logger.info("PacketEngine starting on interface '%s' (simulation=%s)",
                    self.interface, self.simulation_mode)

        if self.simulation_mode:
            # In simulation mode, generate synthetic traffic for testing
            asyncio.create_task(self._simulation_producer())
        else:
            # Real sniffing — runs Scapy AsyncSniffer in a thread
            self._start_scapy_sniffer()

        # Flow expiry loop runs as a background coroutine
        asyncio.create_task(self._flow_expiry_loop())
        logger.info("PacketEngine started successfully.")

    async def stop(self) -> None:
        """Gracefully stop sniffing and flush remaining flows."""
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning("Error stopping sniffer: %s", e)
        logger.info("PacketEngine stopped. Packets captured: %d, Flows finalized: %d",
                    self._packets_captured, self._flows_finalized)

    # ------------------------------------------------------------------
    # Internal: Scapy sniffing
    # ------------------------------------------------------------------

    def _start_scapy_sniffer(self) -> None:
        """
        Launch Scapy's AsyncSniffer in a daemon thread.
        AsyncSniffer runs its own thread internally — we capture a reference
        so we can stop it cleanly.
        """
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,          # Don't accumulate packets in memory
                filter="ip",          # BPF filter: IPv4 only
                # promisc=True is the default on Linux when running as root
            )
            self._sniffer.start()
            logger.info("Scapy AsyncSniffer launched on '%s'", self.interface)
        except ImportError:
            logger.error("Scapy not installed — falling back to simulation mode")
            self.simulation_mode = True
            asyncio.ensure_future(self._simulation_producer())
        except Exception as e:
            logger.error("Failed to start Scapy sniffer: %s. Falling back to simulation.", e)
            self.simulation_mode = True
            asyncio.ensure_future(self._simulation_producer())

    def _on_packet(self, pkt) -> None:
        """
        Scapy packet callback — called in Scapy's sniffer thread.
        Must be fast; all heavy work is deferred to the flow expiry loop.
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

            # Extract transport layer fields
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                # TCP flags: SYN bit is 0x02
                is_syn = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)
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
            self.flow_table.update_or_create(flow_key, pkt_size, is_syn)
            self._packets_captured += 1

            # Periodic stats logging
            if self._packets_captured % 10_000 == 0:
                logger.info(
                    "Captured %d pkts | Active flows: %d",
                    self._packets_captured,
                    self.flow_table.active_count,
                )
        except Exception as e:
            logger.debug("Packet parse error: %s", e)

    # ------------------------------------------------------------------
    # Internal: Flow expiry loop
    # ------------------------------------------------------------------

    async def _flow_expiry_loop(self) -> None:
        """
        Periodically collect expired flows and push their feature vectors
        to the feature_queue. Runs every (idle_timeout / 4) seconds.
        """
        check_interval = max(5.0, self.idle_timeout / 4)
        logger.debug("Flow expiry loop running every %.1fs", check_interval)

        while self._running:
            await asyncio.sleep(check_interval)
            try:
                expired = self.flow_table.collect_expired()
                for flow_key, record in expired:
                    if record.pkt_count < 2:
                        # Skip single-packet "flows" — not enough data for ML
                        continue
                    feature_vec = record.to_feature_vector()
                    metadata = {
                        "src_ip": record.src_ip,
                        "dst_ip": record.dst_ip,
                        "src_port": record.src_port,
                        "dst_port": record.dst_port,
                        "protocol": record.protocol,
                    }
                    try:
                        # Non-blocking put — drop if queue is full to avoid back-pressure
                        self.feature_queue.put_nowait((feature_vec, metadata))
                        self._flows_finalized += 1
                    except asyncio.QueueFull:
                        logger.warning("Feature queue full — dropping flow %s", flow_key)
            except Exception as e:
                logger.error("Flow expiry loop error: %s", e)

    # ------------------------------------------------------------------
    # Internal: Simulation mode producer
    # ------------------------------------------------------------------

    async def _simulation_producer(self) -> None:
        """
        Generates synthetic flow feature vectors mimicking real traffic.
        Useful for testing on Windows/macOS without root access.
        Produces a mix of ~85% normal traffic and ~15% simulated attacks.
        """
        logger.info("Simulation mode active — generating synthetic traffic flows")
        rng = np.random.default_rng(42)
        flow_id = 0

        while self._running:
            is_attack = rng.random() < 0.15
            flow_id += 1

            if is_attack:
                # Simulate DDoS / port scan characteristics
                pkt_count = float(rng.integers(500, 5000))
                byte_count = pkt_count * rng.uniform(40, 80)   # small packets = SYN flood
                avg_iat = rng.uniform(0.0001, 0.002)           # very fast
                syn_ratio = rng.uniform(0.8, 1.0)              # mostly SYN
                src_ip_int = float(rng.integers(0x01000000, 0xFFFFFFFE))
                dst_port = float(rng.choice([80, 443, 22, 3306]))
            else:
                # Normal HTTPS/HTTP-like traffic
                pkt_count = float(rng.integers(5, 200))
                byte_count = pkt_count * rng.uniform(200, 1500)
                avg_iat = rng.uniform(0.01, 0.5)
                syn_ratio = rng.uniform(0.0, 0.1)
                src_ip_int = float(rng.integers(0xC0A80000, 0xC0A8FFFF))  # 192.168.x.x
                dst_port = float(rng.choice([80, 443, 8080]))

            feature_vec = np.array([
                src_ip_int,                             # src_ip_int
                float(0xC0A80001),                      # dst_ip_int (server)
                float(rng.integers(1024, 65535)),       # src_port
                dst_port,                               # dst_port
                float(rng.choice([6, 17, 1])),          # protocol
                pkt_count,
                byte_count,
                byte_count / max(pkt_count, 1),         # avg_pkt_size
                float(rng.uniform(10, 200)),            # std_pkt_size
                avg_iat * 0.1,                          # min_iat
                avg_iat * 5.0,                          # max_iat
                avg_iat,                                # avg_iat
                pkt_count * avg_iat,                    # flow_duration
                syn_ratio,
            ], dtype=np.float32)

            metadata = {
                "src_ip": "10.0.0." + str(rng.integers(1, 254)),
                "dst_ip": "192.168.0.1",
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": int(dst_port),
                "protocol": int(rng.choice([6, 17, 1])),
                "simulated_attack": is_attack,
            }

            try:
                self.feature_queue.put_nowait((feature_vec, metadata))
            except asyncio.QueueFull:
                pass  # Silent drop in simulation mode

            # Throttle to ~100 flows/sec in simulation
            await asyncio.sleep(0.01)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return current engine statistics."""
        return {
            "packets_captured": self._packets_captured,
            "flows_finalized": self._flows_finalized,
            "active_flows": self.flow_table.active_count,
            "queue_depth": self.feature_queue.qsize(),
            "simulation_mode": self.simulation_mode,
        }


# ---------------------------------------------------------------------------
# Module entry-point for standalone testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import yaml

    logging.basicConfig(level=logging.INFO)

    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)

    # Force simulation mode when running standalone
    cfg["firewall"]["simulation_mode"] = True

    async def _test():
        engine = PacketEngine(cfg)
        await engine.start()
        for _ in range(10):
            await asyncio.sleep(1.0)
            vec, meta = await engine.feature_queue.get()
            print(f"Flow: {meta['src_ip']} -> {meta['dst_ip']} | vec shape: {vec.shape}")
        await engine.stop()

    asyncio.run(_test())
