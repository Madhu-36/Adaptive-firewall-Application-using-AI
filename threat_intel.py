"""
threat_intel.py
===============
Global Threat Intelligence (OSINT) Integration Module.
Periodically synchronizes known malicious IP addresses from global feeds
(e.g., Spamhaus, AlienVault OTX, CISA feeds) to provide the RL Agent
with advanced preemptive context before an attack even occurs.
"""

import asyncio
import logging
import time
from typing import Set

logger = logging.getLogger(__name__)

class ThreatIntelligenceFeed:
    def __init__(self, sync_interval_sec: int = 3600):
        self.sync_interval = sync_interval_sec
        self.malicious_ips: Set[str] = set()
        self.last_sync = 0.0

    async def start_sync_loop(self):
        """Background daemon to fetch OSINT feeds."""
        while True:
            logger.info("Synchronizing Global Threat Intelligence feeds...")
            # Simulated fetch from remote OSINT endpoints
            await asyncio.sleep(2) 
            self._update_internal_database()
            logger.info(f"Threat Intel Sync complete. Tracking {len(self.malicious_ips)} malicious subnets.")
            await asyncio.sleep(self.sync_interval)

    def _update_internal_database(self):
        # In a real environment, this makes REST calls to AlienVault OTX
        self.malicious_ips.update([
            "185.112.98.44", "103.22.201.76", "91.208.15.119",
            "45.134.20.11", "193.201.224.218"
        ])

    def check_ip(self, ip_address: str) -> float:
        """Returns a baseline threat multiplier if IP is globally blacklisted."""
        return 2.5 if ip_address in self.malicious_ips else 1.0
