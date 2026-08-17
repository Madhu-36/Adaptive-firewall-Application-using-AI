"""
kernel_enforcer.py
==================
Kernel-level nftables rule enforcement engine.

Interfaces directly with the Linux kernel via nftables to:
  - Inject DROP rules for malicious source IPs in < 50ms.
  - Apply per-IP rate limiting via nftables meters.
  - Maintain a rule registry with per-rule TTL and threat scores.
  - Auto-expire stale rules via background cleanup.
  - Support dry-run mode for testing on non-Linux systems.

nftables Table Structure:
  table inet firewall_ai {
    set blackhole {
      type ipv4_addr
      flags timeout
    }
    chain input {
      type filter hook input priority 0; policy accept;
      ip saddr @blackhole drop
    }
    chain rate_limits {
      type filter hook input priority -10; policy accept;
    }
  }
"""

import asyncio
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import config

logger = logging.getLogger("firewall.kernel")


@dataclass
class KernelRule:
    """
    Represents a single active firewall rule with lifecycle metadata.
    """
    src_ip: str
    action: str                          # "DROP_IP" or "RATE_LIMIT_IP"
    threat_type: str                     # e.g., "SYN_FLOOD"
    anomaly_score: float
    created_at: float = field(default_factory=time.monotonic)
    ttl_sec: float = config.RULE_TTL_DEFAULT
    nft_handle: Optional[int] = None
    hit_count: int = 0
    last_refreshed: float = field(default_factory=time.monotonic)

    @property
    def age_seconds(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def is_expired(self) -> bool:
        return self.age_seconds > self.ttl_sec

    def refresh(self, new_score: float) -> None:
        """Extend TTL when the same IP attacks again."""
        self.ttl_sec = min(self.ttl_sec * 1.5, config.RULE_TTL_MAX)
        self.anomaly_score = max(self.anomaly_score, new_score)
        self.last_refreshed = time.monotonic()

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "action": self.action,
            "threat_type": self.threat_type,
            "anomaly_score": round(self.anomaly_score, 4),
            "age_seconds": round(self.age_seconds, 1),
            "ttl_sec": self.ttl_sec,
            "hit_count": self.hit_count,
        }


class RuleRegistry:
    """Thread-safe in-memory registry of active firewall rules."""

    def __init__(self):
        self._rules: Dict[str, KernelRule] = {}
        self._lock = threading.RLock()

    def add(self, rule: KernelRule) -> None:
        with self._lock:
            self._rules[rule.src_ip] = rule

    def get(self, src_ip: str) -> Optional[KernelRule]:
        with self._lock:
            return self._rules.get(src_ip)

    def remove(self, src_ip: str) -> Optional[KernelRule]:
        with self._lock:
            return self._rules.pop(src_ip, None)

    def get_expired(self) -> List[KernelRule]:
        with self._lock:
            return [r for r in self._rules.values() if r.is_expired]

    def get_all(self) -> List[KernelRule]:
        with self._lock:
            return list(self._rules.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._rules)

    def __contains__(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._rules


class KernelEnforcer:
    """
    Primary interface for kernel-level nftables rule management.

    Usage:
        enforcer = KernelEnforcer()
        enforcer.setup_tables()
        await enforcer.start_cleanup_loop()
        latency_ms = await enforcer.apply_action("1.2.3.4", "DROP_IP", "SYN_FLOOD", 0.95)
    """

    def __init__(self):
        # Detect if we can actually run nftables
        self.dry_run = config.SIMULATION_MODE or not self._check_nft_available()
        if self.dry_run:
            logger.warning("KernelEnforcer: DRY-RUN mode (nftables unavailable or simulation)")

        self.registry = RuleRegistry()
        self._whitelist: Set[str] = set(config.WHITELIST_IPS)
        self._running = False

        # Metrics
        self._total_blocks = 0
        self._total_rate_limits = 0
        self._total_removes = 0
        self._total_latency_sum = 0.0
        self._total_latency_count = 0

    @staticmethod
    def _check_nft_available() -> bool:
        """Check if nft command is available (Linux only)."""
        try:
            result = subprocess.run(
                ["nft", "--version"], capture_output=True, timeout=2,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def setup_tables(self) -> bool:
        """
        Create nftables table, sets, and chains on startup.
        Uses nft set with timeout flag for automatic IP expiry.
        """
        nft_commands = [
            f"add table inet {config.NFT_TABLE_NAME}",
            f"add set inet {config.NFT_TABLE_NAME} {config.NFT_SET_BLACKHOLE} {{ type ipv4_addr; flags timeout; }}",
            f"add chain inet {config.NFT_TABLE_NAME} {config.NFT_CHAIN_INPUT} {{ type filter hook input priority 0; policy accept; }}",
            f"add chain inet {config.NFT_TABLE_NAME} {config.NFT_CHAIN_RATE} {{ type filter hook input priority -10; policy accept; }}",
            f"add rule inet {config.NFT_TABLE_NAME} {config.NFT_CHAIN_INPUT} ip saddr @{config.NFT_SET_BLACKHOLE} counter drop",
        ]

        success = True
        for cmd in nft_commands:
            if not self._run_nft(["nft"] + cmd.split()):
                success = False

        if success:
            logger.info("nftables table '%s' initialized successfully", config.NFT_TABLE_NAME)
        return success

    # ------------------------------------------------------------------
    # Rule Injection
    # ------------------------------------------------------------------

    async def apply_action(
        self,
        src_ip: str,
        action_name: str,
        threat_type: str = "UNKNOWN",
        anomaly_score: float = 0.0,
    ) -> float:
        """
        Apply a firewall action for the given source IP.

        Args:
            src_ip:        Source IP address
            action_name:   "DROP_IP", "RATE_LIMIT_IP", "REMOVE_RULE", or "ALLOW"
            threat_type:   Classification label
            anomaly_score: Detection confidence

        Returns:
            Mitigation latency in milliseconds.
        """
        t_start = time.perf_counter()

        # Validate IP
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            logger.warning("Invalid IP address: %s", src_ip)
            return 0.0

        # Never block whitelisted IPs
        if src_ip in self._whitelist:
            logger.debug("IP %s is whitelisted", src_ip)
            return 0.0

        if action_name == "ALLOW":
            return 0.0

        if action_name == "REMOVE_RULE":
            await self.remove_rule(src_ip)
            latency_ms = (time.perf_counter() - t_start) * 1000
            return latency_ms

        # Check if rule already exists
        existing = self.registry.get(src_ip)
        if existing is not None:
            if existing.action == action_name:
                existing.refresh(anomaly_score)
                latency_ms = (time.perf_counter() - t_start) * 1000
                return latency_ms
            else:
                # Escalate or change action
                await self.remove_rule(src_ip)

        # Check capacity
        if len(self.registry) >= config.MAX_KERNEL_RULES:
            logger.warning("Rule capacity reached — emergency cleanup")
            await self._emergency_cleanup()

        # Inject rule
        if action_name == "DROP_IP":
            success = self._inject_drop(src_ip)
            if success:
                self._total_blocks += 1
        elif action_name == "RATE_LIMIT_IP":
            success = self._inject_rate_limit(src_ip)
            if success:
                self._total_rate_limits += 1
        else:
            success = False

        if success:
            rule = KernelRule(
                src_ip=src_ip,
                action=action_name,
                threat_type=threat_type,
                anomaly_score=anomaly_score,
                ttl_sec=config.RULE_TTL_DEFAULT,
            )
            self.registry.add(rule)

        latency_ms = (time.perf_counter() - t_start) * 1000
        self._total_latency_sum += latency_ms
        self._total_latency_count += 1

        if latency_ms > config.MITIGATION_LATENCY_TARGET_MS:
            logger.warning(
                "Rule injection exceeded %dms target: %.2fms",
                config.MITIGATION_LATENCY_TARGET_MS, latency_ms,
            )
        else:
            logger.info(
                "%s rule injected for %s | score=%.3f | latency=%.2fms",
                action_name, src_ip, anomaly_score, latency_ms,
            )

        return latency_ms

    def _inject_drop(self, src_ip: str) -> bool:
        """
        Add IP to the nftables blackhole set with timeout.
        Uses: nft add element inet firewall_ai blackhole { <IP> timeout 300s }
        """
        cmd = [
            "nft", "add", "element", "inet", config.NFT_TABLE_NAME,
            config.NFT_SET_BLACKHOLE,
            "{", src_ip, "timeout", f"{config.RULE_TTL_DEFAULT}s", "}",
        ]
        return self._run_nft(cmd)

    def _inject_rate_limit(self, src_ip: str) -> bool:
        """
        Add per-IP rate limit rule.
        Uses nftables meter for per-IP tracking.
        """
        # Accept up to rate_limit_pps, drop excess
        cmd_accept = [
            "nft", "add", "rule", "inet", config.NFT_TABLE_NAME,
            config.NFT_CHAIN_RATE,
            "ip", "saddr", src_ip,
            "limit", "rate", f"{config.RATE_LIMIT_PPS}/second",
            "counter", "accept",
        ]
        cmd_drop = [
            "nft", "add", "rule", "inet", config.NFT_TABLE_NAME,
            config.NFT_CHAIN_RATE,
            "ip", "saddr", src_ip,
            "counter", "drop",
        ]
        return self._run_nft(cmd_accept) and self._run_nft(cmd_drop)

    # ------------------------------------------------------------------
    # Rule Removal
    # ------------------------------------------------------------------

    async def remove_rule(self, src_ip: str) -> bool:
        """Remove an active rule for the given IP."""
        rule = self.registry.get(src_ip)
        if rule is None:
            return False

        if rule.action == "DROP_IP":
            # Remove from blackhole set
            cmd = [
                "nft", "delete", "element", "inet", config.NFT_TABLE_NAME,
                config.NFT_SET_BLACKHOLE,
                "{", src_ip, "}",
            ]
            self._run_nft(cmd)

        self.registry.remove(src_ip)
        self._total_removes += 1
        logger.info("Removed %s rule for %s", rule.action, src_ip)
        return True

    # ------------------------------------------------------------------
    # Cleanup Loop
    # ------------------------------------------------------------------

    async def start_cleanup_loop(self) -> None:
        """Background rule expiry loop."""
        self._running = True
        logger.info("Kernel cleanup loop started (interval=%ds)", config.RULE_CLEANUP_INTERVAL)
        while self._running:
            await asyncio.sleep(config.RULE_CLEANUP_INTERVAL)
            await self._run_cleanup()

    async def _run_cleanup(self) -> None:
        """Remove all expired rules."""
        expired = self.registry.get_expired()
        if not expired:
            return
        logger.info("Cleanup: removing %d expired rules", len(expired))
        for rule in expired:
            await self.remove_rule(rule.src_ip)

    async def _emergency_cleanup(self) -> None:
        """Remove lowest-threat rules when capacity is reached."""
        all_rules = self.registry.get_all()
        all_rules.sort(key=lambda r: r.anomaly_score)
        to_remove = all_rules[:max(1, len(all_rules) // 5)]
        logger.warning("Emergency cleanup: removing %d low-threat rules", len(to_remove))
        for rule in to_remove:
            await self.remove_rule(rule.src_ip)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # nftables subprocess helper
    # ------------------------------------------------------------------

    def _run_nft(self, cmd: List[str]) -> bool:
        """Execute an nft command. In dry-run mode, only logs."""
        if self.dry_run:
            logger.info("[DRY-RUN] %s", " ".join(cmd))
            return True
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                logger.error("nft failed: %s | stderr: %s", " ".join(cmd), result.stderr.strip())
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("nft command timed out: %s", " ".join(cmd))
            return False
        except FileNotFoundError:
            logger.error("nft not found — switching to dry-run")
            self.dry_run = True
            return False
        except Exception as e:
            logger.error("nft error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        avg_lat = (
            self._total_latency_sum / max(self._total_latency_count, 1)
        )
        return {
            "active_rules": len(self.registry),
            "total_blocks": self._total_blocks,
            "total_rate_limits": self._total_rate_limits,
            "total_removes": self._total_removes,
            "avg_latency_ms": round(avg_lat, 2),
            "dry_run": self.dry_run,
        }

    def list_rules(self) -> List[dict]:
        return [r.to_dict() for r in self.registry.get_all()]

    def flush_all(self) -> bool:
        """Emergency: remove ALL rules."""
        logger.warning("Flushing ALL firewall rules!")
        cmd = ["nft", "flush", "table", "inet", config.NFT_TABLE_NAME]
        success = self._run_nft(cmd)
        if success:
            with self.registry._lock:
                self.registry._rules.clear()
        return success
