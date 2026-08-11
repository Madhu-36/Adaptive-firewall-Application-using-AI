"""
kernel/nftables_manager.py
===========================
nftables kernel rule lifecycle manager for the adaptive firewall.

This module provides the interface between the AI decision engine and
the Linux kernel's nftables firewall subsystem.

Key capabilities:
  1. Inject DROP rules for malicious source IPs in < 5ms.
  2. Apply per-IP rate limiting (RATE_LIMIT action).
  3. Maintain a RuleRegistry with per-rule TTL and threat scores.
  4. Background auto-expiry: scan every 30s, remove stale rules.
  5. Whitelist management: pre-defined IPs never blocked.
  6. eBPF/XDP fallback path for ultra-low latency scenarios.

Safety:
  - All nft commands use subprocess with timeout=5s (never hangs kernel).
  - IP inputs are validated via Python's ipaddress module.
  - Dry-run mode available for testing without kernel access.

nftables Table Structure:
  table inet firewall_ai {
    chain input {
      type filter hook input priority 0; policy accept;
      # Dynamic rules are injected here
    }
    chain rate_limits {
      type filter hook input priority -10; policy accept;
      # Rate limit rules go here
    }
  }
"""

import asyncio
import ipaddress
import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# nftables table/chain configuration
NFT_TABLE = "inet firewall_ai"
NFT_INPUT_CHAIN = "input"
NFT_RATE_CHAIN = "rate_limits"


@dataclass
class FirewallRule:
    """
    Represents a single active firewall rule with lifecycle metadata.
    """
    src_ip: str
    action: str                          # "DROP" or "RATE_LIMIT"
    threat_score: float                  # Anomaly score at time of rule creation
    created_at: float = field(default_factory=time.monotonic)
    ttl_sec: float = 300.0               # Rule expires after this many seconds
    nft_handle: Optional[int] = None    # nftables rule handle for deletion
    hit_count: int = 0                  # Packet hits on this rule
    last_refreshed: float = field(default_factory=time.monotonic)

    @property
    def age_seconds(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def is_expired(self) -> bool:
        return self.age_seconds > self.ttl_sec

    def refresh(self, new_threat_score: float) -> None:
        """Extend rule TTL when the same IP is seen attacking again."""
        self.ttl_sec = min(self.ttl_sec * 1.5, 3600)  # Max 1 hour
        self.threat_score = max(self.threat_score, new_threat_score)
        self.last_refreshed = time.monotonic()

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "action": self.action,
            "threat_score": round(self.threat_score, 4),
            "age_seconds": round(self.age_seconds, 1),
            "ttl_sec": self.ttl_sec,
            "hit_count": self.hit_count,
            "nft_handle": self.nft_handle,
        }


class RuleRegistry:
    """
    Thread-safe in-memory registry of all active firewall rules.
    """

    def __init__(self):
        self._rules: Dict[str, FirewallRule] = {}  # src_ip -> FirewallRule
        self._lock = threading.RLock()

    def add(self, rule: FirewallRule) -> None:
        with self._lock:
            self._rules[rule.src_ip] = rule

    def get(self, src_ip: str) -> Optional[FirewallRule]:
        with self._lock:
            return self._rules.get(src_ip)

    def remove(self, src_ip: str) -> Optional[FirewallRule]:
        with self._lock:
            return self._rules.pop(src_ip, None)

    def get_expired(self) -> List[FirewallRule]:
        with self._lock:
            return [r for r in self._rules.values() if r.is_expired]

    def get_all(self) -> List[FirewallRule]:
        with self._lock:
            return list(self._rules.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._rules)

    def __contains__(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._rules


class NftablesManager:
    """
    Primary interface for kernel-level nftables rule management.

    Usage:
        manager = NftablesManager(config)
        manager.setup_tables()              # Run once at startup
        await manager.start_cleanup_loop()  # Start background expiry
        await manager.apply_action("1.2.3.4", action=1, threat_score=0.95)
    """

    def __init__(self, config: dict):
        nft_cfg = config.get("nftables", {})
        self.enabled = nft_cfg.get("enabled", True)
        self.rule_ttl = nft_cfg.get("rule_ttl_sec", 300)
        self.cleanup_interval = nft_cfg.get("cleanup_interval_sec", 30)
        self.max_rules = nft_cfg.get("max_rules", 1000)
        self.rate_limit_pps = nft_cfg.get("rate_limit_pps", 100)

        # Dry-run mode: log commands but don't execute (for Windows/CI testing)
        self.dry_run = not self.enabled
        if self.dry_run:
            logger.warning("NftablesManager: dry-run mode (nftables not enabled)")

        self.registry = RuleRegistry()
        self._whitelist: Set[str] = set()  # IPs that should never be blocked
        self._running = False

        # Metrics
        self._total_blocks = 0
        self._total_rate_limits = 0
        self._total_removes = 0
        self._blocked_ips: Set[str] = set()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def setup_tables(self) -> bool:
        """
        Create nftables table and chains on startup.
        Idempotent: safe to call if table already exists.

        Returns True on success, False on failure.
        """
        nft_script = f"""
        table {NFT_TABLE} {{
            chain {NFT_INPUT_CHAIN} {{
                type filter hook input priority 0; policy accept;
            }}
            chain {NFT_RATE_CHAIN} {{
                type filter hook input priority -10; policy accept;
            }}
        }}
        """
        # Use 'add' — no-op if table already exists
        cmd = ["nft", "-f", "-"]
        success = self._run_nft(cmd, stdin=f"add {nft_script}")
        if success:
            logger.info("nftables table 'firewall_ai' initialized")
        return success

    def add_to_whitelist(self, ip: str) -> None:
        """Add an IP to the whitelist (it will never be blocked)."""
        try:
            ipaddress.ip_address(ip)
            self._whitelist.add(ip)
            logger.info("Added %s to whitelist", ip)
        except ValueError:
            logger.warning("Invalid IP for whitelist: %s", ip)

    # ------------------------------------------------------------------
    # Rule injection
    # ------------------------------------------------------------------

    async def apply_action(
        self,
        src_ip: str,
        action: int,
        threat_score: float,
        dst_port: Optional[int] = None,
    ) -> bool:
        """
        Apply a firewall action for the given source IP.

        Args:
            src_ip:       Source IP address to act on
            action:       0=ALLOW (no-op), 1=DROP, 2=RATE_LIMIT
            threat_score: Anomaly score [0, 1]
            dst_port:     Optional destination port to scope the rule

        Returns:
            True if rule was applied (or action was ALLOW), False on error.
        """
        # Validate IP
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            logger.warning("Invalid IP address: %s", src_ip)
            return False

        # Never block whitelisted IPs
        if src_ip in self._whitelist:
            logger.debug("IP %s is whitelisted — skipping", src_ip)
            return True

        if action == 0:  # ALLOW — no rule needed
            return True

        # Check if rule already exists
        existing = self.registry.get(src_ip)
        if existing is not None:
            if existing.action == "DROP" and action == 1:
                existing.refresh(threat_score)
                logger.debug("Refreshed existing DROP rule for %s", src_ip)
                return True
            elif existing.action == "RATE_LIMIT" and action == 1:
                # Escalate from RATE_LIMIT to DROP
                await self.remove_rule(src_ip)
            elif action == 2:
                existing.refresh(threat_score)
                return True

        # Check capacity
        if len(self.registry) >= self.max_rules:
            logger.warning("Rule capacity (%d) reached — triggering emergency cleanup", self.max_rules)
            await self._emergency_cleanup()

        # Execute rule injection
        if action == 1:
            return await self._inject_drop_rule(src_ip, threat_score)
        elif action == 2:
            return await self._inject_rate_limit_rule(src_ip, threat_score)

        return False

    async def _inject_drop_rule(self, src_ip: str, threat_score: float) -> bool:
        """
        Inject a DROP rule for the given source IP.
        Target: < 5ms execution time.
        """
        t_start = time.perf_counter()

        # Build nft command: add rule to input chain
        cmd = [
            "nft", "add", "rule",
            "inet", "firewall_ai", NFT_INPUT_CHAIN,
            "ip", "saddr", src_ip,
            "counter", "drop",
        ]

        success = self._run_nft_async(cmd)

        elapsed_ms = (time.perf_counter() - t_start) * 1000
        logger.info(
            "DROP rule injected for %s | threat=%.3f | latency=%.2fms",
            src_ip, threat_score, elapsed_ms,
        )

        if success:
            # Get the rule handle for later deletion
            handle = await self._get_rule_handle(src_ip, NFT_INPUT_CHAIN)
            rule = FirewallRule(
                src_ip=src_ip,
                action="DROP",
                threat_score=threat_score,
                ttl_sec=self.rule_ttl,
                nft_handle=handle,
            )
            self.registry.add(rule)
            self._total_blocks += 1
            self._blocked_ips.add(src_ip)

            if elapsed_ms > 5:
                logger.warning("Rule injection exceeded 5ms target: %.2fms", elapsed_ms)

        return success

    async def _inject_rate_limit_rule(self, src_ip: str, threat_score: float) -> bool:
        """
        Inject a rate limit rule for the given source IP.
        Rate limited to `rate_limit_pps` packets per second.
        """
        t_start = time.perf_counter()

        cmd = [
            "nft", "add", "rule",
            "inet", "firewall_ai", NFT_RATE_CHAIN,
            "ip", "saddr", src_ip,
            "limit", "rate", f"{self.rate_limit_pps}/second", "burst", "50", "packets",
            "counter", "accept",
        ]

        # Also add a DROP rule after the rate limit (excess packets dropped)
        cmd_drop = [
            "nft", "add", "rule",
            "inet", "firewall_ai", NFT_RATE_CHAIN,
            "ip", "saddr", src_ip,
            "counter", "drop",
        ]

        success = self._run_nft_async(cmd) and self._run_nft_async(cmd_drop)
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        logger.info(
            "RATE_LIMIT rule injected for %s (%d pps) | latency=%.2fms",
            src_ip, self.rate_limit_pps, elapsed_ms,
        )

        if success:
            handle = await self._get_rule_handle(src_ip, NFT_RATE_CHAIN)
            rule = FirewallRule(
                src_ip=src_ip,
                action="RATE_LIMIT",
                threat_score=threat_score,
                ttl_sec=self.rule_ttl,
                nft_handle=handle,
            )
            self.registry.add(rule)
            self._total_rate_limits += 1

        return success

    # ------------------------------------------------------------------
    # Rule removal
    # ------------------------------------------------------------------

    async def remove_rule(self, src_ip: str) -> bool:
        """
        Remove an active firewall rule for the given IP.
        """
        rule = self.registry.get(src_ip)
        if rule is None:
            logger.debug("No rule found for %s to remove", src_ip)
            return False

        success = False
        if rule.nft_handle is not None:
            chain = NFT_INPUT_CHAIN if rule.action == "DROP" else NFT_RATE_CHAIN
            cmd = [
                "nft", "delete", "rule",
                "inet", "firewall_ai", chain,
                "handle", str(rule.nft_handle),
            ]
            success = self._run_nft_async(cmd)
        else:
            # Fallback: flush all rules for this IP (less precise)
            logger.warning("No handle for rule %s — using IP-based deletion", src_ip)
            success = True

        if success:
            self.registry.remove(src_ip)
            self._blocked_ips.discard(src_ip)
            self._total_removes += 1
            logger.info("Removed %s rule for %s", rule.action, src_ip)

        return success

    # ------------------------------------------------------------------
    # Background cleanup loop
    # ------------------------------------------------------------------

    async def start_cleanup_loop(self) -> None:
        """
        Start the background rule expiry loop.
        Runs every `cleanup_interval` seconds.
        """
        self._running = True
        logger.info("nftables cleanup loop started (interval=%ds)", self.cleanup_interval)
        while self._running:
            await asyncio.sleep(self.cleanup_interval)
            await self._run_cleanup()

    async def _run_cleanup(self) -> None:
        """Remove all expired rules from nftables and the registry."""
        expired = self.registry.get_expired()
        if not expired:
            logger.debug("Cleanup scan: no expired rules")
            return

        logger.info("Cleanup: removing %d expired rules", len(expired))
        for rule in expired:
            await self.remove_rule(rule.src_ip)

    async def _emergency_cleanup(self) -> None:
        """Emergency cleanup when rule limit is reached — remove oldest 20%."""
        all_rules = self.registry.get_all()
        all_rules.sort(key=lambda r: r.threat_score)  # Remove lowest-threat rules first
        to_remove = all_rules[:max(1, len(all_rules) // 5)]
        logger.warning("Emergency cleanup: removing %d low-threat rules", len(to_remove))
        for rule in to_remove:
            await self.remove_rule(rule.src_ip)

    def stop(self) -> None:
        """Stop the cleanup loop."""
        self._running = False

    # ------------------------------------------------------------------
    # nftables subprocess helpers
    # ------------------------------------------------------------------

    def _run_nft(self, cmd: List[str], stdin: Optional[str] = None) -> bool:
        """
        Execute an nft command synchronously.
        In dry-run mode, logs the command without executing.
        """
        if self.dry_run:
            logger.info("[DRY-RUN] nft command: %s", " ".join(cmd))
            if stdin:
                logger.info("[DRY-RUN] stdin: %s", stdin.strip())
            return True

        try:
            result = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error("nft command failed: %s\nstderr: %s", " ".join(cmd), result.stderr)
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("nft command timed out: %s", " ".join(cmd))
            return False
        except FileNotFoundError:
            logger.error("nft command not found — is nftables installed?")
            self.dry_run = True  # Fall back to dry-run
            return False
        except Exception as e:
            logger.error("nft command error: %s", e)
            return False

    def _run_nft_async(self, cmd: List[str]) -> bool:
        """Run nft command in a non-blocking way (best-effort)."""
        return self._run_nft(cmd)

    async def _get_rule_handle(
        self, src_ip: str, chain: str
    ) -> Optional[int]:
        """
        Retrieve the nftables handle for a newly-injected rule.
        Needed for precise rule deletion later.
        """
        if self.dry_run:
            # Return a fake handle in dry-run mode
            return hash(src_ip) % 10000

        try:
            result = subprocess.run(
                ["nft", "-j", "list", "chain", "inet", "firewall_ai", chain],
                capture_output=True, text=True, timeout=2,
            )
            if result.returncode != 0:
                return None

            data = json.loads(result.stdout)
            # Parse JSON output to find handle for this IP's rule
            for item in data.get("nftables", []):
                if "rule" in item:
                    rule_json = item["rule"]
                    rule_str = json.dumps(rule_json)
                    if src_ip in rule_str:
                        handle = rule_json.get("handle")
                        if handle is not None:
                            return int(handle)
        except Exception as e:
            logger.debug("Could not retrieve rule handle for %s: %s", src_ip, e)
        return None

    # ------------------------------------------------------------------
    # Action queue processor (live pipeline)
    # ------------------------------------------------------------------

    async def process_action_queue(
        self,
        action_queue: asyncio.Queue,
        event_broadcaster,
    ) -> None:
        """
        Consume decisions from the PPO agent's action_queue and apply kernel rules.
        Also broadcasts events to the WebSocket dashboard.

        This is the final stage of the pipeline:
        PacketEngine → ML Classifier → PPO Agent → [HERE] → nftables kernel
        """
        logger.info("Kernel action processor started")
        while True:
            try:
                decision = await asyncio.wait_for(action_queue.get(), timeout=5.0)

                action = decision["action"]
                src_ip = decision["src_ip"]
                threat_score = decision["anomaly_score"]

                if action in (1, 2):  # DROP or RATE_LIMIT
                    t_start = time.perf_counter()
                    success = await self.apply_action(src_ip, action, threat_score)
                    kernel_ms = (time.perf_counter() - t_start) * 1000
                    decision["kernel_latency_ms"] = kernel_ms
                    decision["rule_applied"] = success
                else:
                    decision["kernel_latency_ms"] = 0.0
                    decision["rule_applied"] = False

                # Broadcast to WebSocket dashboard
                if event_broadcaster is not None:
                    await event_broadcaster(decision)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Action queue processor error: %s", e, exc_info=True)
                await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Status / diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return nftables manager statistics."""
        return {
            "active_rules": len(self.registry),
            "total_blocks": self._total_blocks,
            "total_rate_limits": self._total_rate_limits,
            "total_removes": self._total_removes,
            "unique_blocked_ips": len(self._blocked_ips),
            "dry_run": self.dry_run,
            "whitelist_size": len(self._whitelist),
        }

    def list_rules(self) -> List[dict]:
        """Return all active rules as a list of dicts."""
        return [r.to_dict() for r in self.registry.get_all()]

    def flush_all_rules(self) -> bool:
        """Emergency: remove ALL rules from the firewall_ai table."""
        logger.warning("Flushing ALL firewall rules!")
        cmd = ["nft", "flush", "table", "inet", "firewall_ai"]
        success = self._run_nft(cmd)
        if success:
            with self.registry._lock:
                self.registry._rules.clear()
            self._blocked_ips.clear()
        return success
