"""
attack_generator.py
===================
Interactive Multi-Vector Cyberattack Simulation Suite.

Enables real-time, on-demand cyberattack injection against the adaptive firewall
to test detection accuracy, XAI attribution, and sub-millisecond kernel mitigation.

Supported Vectors:
  1. SYN_FLOOD          - High-rate TCP SYN flood (DDoS saturation)
  2. STEALTH_PORT_SCAN  - Multi-port reconnaissance sweep across sensitive ports
  3. UDP_AMPLIFICATION  - High-bandwidth UDP datagram surge
  4. ZERO_DAY_ANOMALY   - Low-and-slow polymorphic flow pattern violating baseline
  5. BRUTE_FORCE_SSH    - Rapid port 22 connection storm
"""

import asyncio
import ipaddress
import logging
import random
import threading
import time
from typing import Dict, Any, Optional

import numpy as np
import config

logger = logging.getLogger("firewall.attack_gen")


class CyberAttackSimulator:
    """
    Manages live synthetic attack campaigns against the firewall pipeline.
    """

    def __init__(self, feature_queue: Optional[asyncio.Queue] = None):
        self.feature_queue = feature_queue
        self._is_attacking = False
        self._current_vector: Optional[str] = None
        self._target_ip = "192.168.1.100"
        self._attacker_ip = "45.154.99.14"
        self._packets_sent = 0
        self._attack_start_time = 0.0
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self._is_attacking

    def get_status(self) -> Dict[str, Any]:
        """Return active simulation telemetry."""
        with self._lock:
            elapsed = time.time() - self._attack_start_time if self._is_attacking else 0.0
            return {
                "is_active": self._is_attacking,
                "current_vector": self._current_vector or "NONE",
                "attacker_ip": self._attacker_ip if self._is_attacking else "N/A",
                "target_ip": self._target_ip if self._is_attacking else "N/A",
                "packets_injected": self._packets_sent,
                "duration_seconds": round(elapsed, 1),
                "intensity_pps": round(self._packets_sent / max(elapsed, 0.1), 1) if self._is_attacking else 0.0,
            }

    def start_attack(self, vector: str, intensity: int = 50, duration_sec: int = 15) -> Dict[str, Any]:
        """
        Start an asynchronous attack simulation campaign.
        """
        with self._lock:
            if self._is_attacking:
                return {"status": "error", "message": f"Simulation already active ({self._current_vector})"}

            vector = vector.upper().strip()
            valid_vectors = ["SYN_FLOOD", "STEALTH_PORT_SCAN", "UDP_AMPLIFICATION", "ZERO_DAY_ANOMALY", "BRUTE_FORCE_SSH"]
            if vector not in valid_vectors:
                return {"status": "error", "message": f"Invalid vector. Choose from {valid_vectors}"}

            self._is_attacking = True
            self._current_vector = vector
            self._packets_sent = 0
            self._attack_start_time = time.time()

            # Assign distinctive attacker IP per vector for easy tracking
            attacker_map = {
                "SYN_FLOOD": f"185.112.{random.randint(10, 200)}.{random.randint(2, 250)}",
                "STEALTH_PORT_SCAN": f"103.22.{random.randint(10, 200)}.{random.randint(2, 250)}",
                "UDP_AMPLIFICATION": f"194.26.{random.randint(10, 200)}.{random.randint(2, 250)}",
                "ZERO_DAY_ANOMALY": f"45.154.{random.randint(10, 200)}.{random.randint(2, 250)}",
                "BRUTE_FORCE_SSH": f"91.208.{random.randint(10, 200)}.{random.randint(2, 250)}",
            }
            self._attacker_ip = attacker_map.get(vector, "198.51.100.99")

            self._thread = threading.Thread(
                target=self._run_campaign,
                args=(vector, intensity, duration_sec),
                daemon=True,
                name=f"attack-sim-{vector}",
            )
            self._thread.start()

            logger.warning("Simulated Cyberattack started: %s from %s", vector, self._attacker_ip)
            return {
                "status": "started",
                "vector": vector,
                "attacker_ip": self._attacker_ip,
                "duration_sec": duration_sec,
            }

    def stop_attack(self) -> Dict[str, Any]:
        """Abort the active simulation."""
        with self._lock:
            if not self._is_attacking:
                return {"status": "idle", "message": "No attack currently running"}
            self._is_attacking = False
            total_sent = self._packets_sent
            vector = self._current_vector
            self._current_vector = None
            logger.info("Simulated attack aborted: %s (Total packets: %d)", vector, total_sent)
            return {"status": "stopped", "vector": vector, "packets_sent": total_sent}

    def _run_campaign(self, vector: str, intensity: int, duration_sec: int) -> None:
        """Background thread executing the synthetic attack flow generation."""
        end_time = time.time() + duration_sec
        delay = max(0.01, 1.0 / max(intensity, 1))

        while time.time() < end_time and self._is_attacking:
            try:
                feature_vec = self._synthesize_attack_vector(vector)
                flow_data = {
                    "src_ip": self._attacker_ip,
                    "dst_ip": self._target_ip,
                    "features": feature_vec,
                    "simulated": True,
                    "attack_campaign": vector,
                    "timestamp": time.time(),
                }

                if self.feature_queue is not None:
                    try:
                        self.feature_queue.put_nowait(flow_data)
                    except Exception:
                        pass

                with self._lock:
                    self._packets_sent += 1

                time.sleep(delay)
            except Exception as e:
                logger.error("Simulation error in %s: %s", vector, e)
                break

        with self._lock:
            self._is_attacking = False
            self._current_vector = None
        logger.info("Attack campaign completed. Total packets injected: %d", self._packets_sent)

    def _synthesize_attack_vector(self, vector: str) -> np.ndarray:
        """
        Generate mathematically accurate 15-dimensional flow feature vectors
        corresponding to specific attack footprints.
        """
        # [0] src_ip_int, [1] dst_ip_int, [2] src_port, [3] dst_port, [4] protocol,
        # [5] pkt_count, [6] byte_count, [7] avg_pkt_len, [8] std_pkt_len,
        # [9] min_iat, [10] max_iat, [11] avg_iat, [12] flow_duration,
        # [13] syn_flag_ratio, [14] rst_flag_ratio

        if vector == "SYN_FLOOD":
            return np.array([
                float(int(ipaddress.IPv4Address(self._attacker_ip))),
                float(int(ipaddress.IPv4Address(self._target_ip))),
                float(random.randint(1024, 65535)),
                80.0,
                6.0,  # TCP
                float(random.randint(1200, 5000)),  # Massive pkt_count
                float(random.randint(60000, 250000)),
                40.0,  # Minimal packet length (SYN packet)
                2.0,
                0.00001,
                0.0005,
                0.00005,  # Sub-millisecond IAT
                float(random.uniform(0.5, 3.0)),
                0.98,  # 98% SYN ratio
                0.01,
            ], dtype=np.float32)

        elif vector == "STEALTH_PORT_SCAN":
            probe_port = float(random.choice([21, 22, 23, 25, 80, 110, 443, 445, 1433, 3306, 3389, 8080]))
            return np.array([
                float(int(ipaddress.IPv4Address(self._attacker_ip))),
                float(int(ipaddress.IPv4Address(self._target_ip))),
                float(random.randint(40000, 60000)),
                probe_port,
                6.0,
                float(random.randint(1, 3)),  # 1-3 probe packets per port
                float(random.randint(60, 180)),
                60.0,
                5.0,
                0.01,
                0.5,
                0.05,
                float(random.uniform(0.1, 1.0)),
                0.90,  # High SYN
                0.00,
            ], dtype=np.float32)

        elif vector == "UDP_AMPLIFICATION":
            return np.array([
                float(int(ipaddress.IPv4Address(self._attacker_ip))),
                float(int(ipaddress.IPv4Address(self._target_ip))),
                53.0,  # DNS reflection source
                float(random.randint(1024, 65535)),
                17.0,  # UDP
                float(random.randint(800, 4000)),
                float(random.randint(1000000, 5000000)),  # Massive bytes
                1420.0,  # Jumbo UDP datagrams
                150.0,
                0.0001,
                0.002,
                0.0003,
                float(random.uniform(0.5, 5.0)),
                0.0,
                0.0,
            ], dtype=np.float32)

        elif vector == "ZERO_DAY_ANOMALY":
            return np.array([
                float(int(ipaddress.IPv4Address(self._attacker_ip))),
                float(int(ipaddress.IPv4Address(self._target_ip))),
                float(random.randint(10000, 50000)),
                8443.0,
                6.0,
                float(random.randint(35, 120)),
                float(random.randint(20000, 80000)),
                float(random.uniform(500.0, 1300.0)),
                float(random.uniform(300.0, 600.0)),  # Wildly skewed std dev
                0.0002,
                4.5,
                0.15,  # Erratic burst & idle cadence
                float(random.uniform(2.0, 8.0)),
                0.40,
                0.35,  # High RST ratio (unusual handshake failures)
            ], dtype=np.float32)

        elif vector == "BRUTE_FORCE_SSH":
            return np.array([
                float(int(ipaddress.IPv4Address(self._attacker_ip))),
                float(int(ipaddress.IPv4Address(self._target_ip))),
                float(random.randint(20000, 60000)),
                22.0,  # SSH port
                6.0,
                float(random.randint(150, 600)),
                float(random.randint(8000, 30000)),
                120.0,
                30.0,
                0.005,
                0.05,
                0.015,
                float(random.uniform(1.0, 6.0)),
                0.60,
                0.20,
            ], dtype=np.float32)

        # Default fallback
        return np.zeros(15, dtype=np.float32)
