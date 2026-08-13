"""
tests/test_nftables_manager.py
==============================
Unit tests for the NftablesManager and RuleRegistry.
All nft subprocess calls are mocked — no kernel access required.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kernel.nftables_manager import (
    FirewallRule,
    NftablesManager,
    RuleRegistry,
)


@pytest.fixture
def config():
    return {
        "nftables": {
            "enabled": False,  # Dry-run mode for all tests
            "rule_ttl_sec": 2,
            "cleanup_interval_sec": 1,
            "max_rules": 10,
            "rate_limit_pps": 50,
        }
    }


@pytest.fixture
def manager(config):
    return NftablesManager(config)


# ---------------------------------------------------------------------------
# FirewallRule tests
# ---------------------------------------------------------------------------

class TestFirewallRule:
    def test_initial_not_expired(self):
        rule = FirewallRule(src_ip="1.2.3.4", action="DROP", threat_score=0.9, ttl_sec=300)
        assert not rule.is_expired

    def test_expired_after_ttl(self):
        rule = FirewallRule(src_ip="1.2.3.4", action="DROP", threat_score=0.9, ttl_sec=0.01)
        time.sleep(0.05)
        assert rule.is_expired

    def test_refresh_extends_ttl(self):
        rule = FirewallRule(src_ip="1.2.3.4", action="DROP", threat_score=0.5, ttl_sec=10)
        original_ttl = rule.ttl_sec
        rule.refresh(0.95)
        assert rule.ttl_sec > original_ttl
        assert rule.threat_score == 0.95

    def test_refresh_caps_at_one_hour(self):
        rule = FirewallRule(src_ip="1.2.3.4", action="DROP", threat_score=0.9, ttl_sec=3600)
        for _ in range(10):
            rule.refresh(0.9)
        assert rule.ttl_sec <= 3600

    def test_to_dict_contains_required_fields(self):
        rule = FirewallRule(src_ip="5.6.7.8", action="RATE_LIMIT", threat_score=0.7, ttl_sec=120)
        d = rule.to_dict()
        assert d["src_ip"] == "5.6.7.8"
        assert d["action"] == "RATE_LIMIT"
        assert "threat_score" in d
        assert "age_seconds" in d
        assert "ttl_sec" in d

    def test_age_increases_over_time(self):
        rule = FirewallRule(src_ip="1.1.1.1", action="DROP", threat_score=0.8, ttl_sec=300)
        age1 = rule.age_seconds
        time.sleep(0.05)
        age2 = rule.age_seconds
        assert age2 > age1


# ---------------------------------------------------------------------------
# RuleRegistry tests
# ---------------------------------------------------------------------------

class TestRuleRegistry:
    def test_add_and_get(self):
        reg = RuleRegistry()
        rule = FirewallRule(src_ip="10.0.0.1", action="DROP", threat_score=0.9)
        reg.add(rule)
        assert reg.get("10.0.0.1") is rule

    def test_contains(self):
        reg = RuleRegistry()
        rule = FirewallRule(src_ip="10.0.0.2", action="DROP", threat_score=0.8)
        reg.add(rule)
        assert "10.0.0.2" in reg
        assert "10.0.0.99" not in reg

    def test_remove(self):
        reg = RuleRegistry()
        rule = FirewallRule(src_ip="10.0.0.3", action="DROP", threat_score=0.7)
        reg.add(rule)
        removed = reg.remove("10.0.0.3")
        assert removed is rule
        assert reg.get("10.0.0.3") is None
        assert len(reg) == 0

    def test_get_expired_returns_only_expired(self):
        reg = RuleRegistry()
        rule_short = FirewallRule(src_ip="1.1.1.1", action="DROP", threat_score=0.9, ttl_sec=0.01)
        rule_long = FirewallRule(src_ip="2.2.2.2", action="DROP", threat_score=0.8, ttl_sec=3600)
        reg.add(rule_short)
        reg.add(rule_long)
        time.sleep(0.05)
        expired = reg.get_expired()
        assert len(expired) == 1
        assert expired[0].src_ip == "1.1.1.1"

    def test_len(self):
        reg = RuleRegistry()
        assert len(reg) == 0
        for i in range(5):
            reg.add(FirewallRule(src_ip=f"10.0.0.{i}", action="DROP", threat_score=0.5))
        assert len(reg) == 5


# ---------------------------------------------------------------------------
# NftablesManager tests (dry-run mode)
# ---------------------------------------------------------------------------

class TestNftablesManager:
    def test_dry_run_mode_enabled_when_nftables_disabled(self, manager):
        assert manager.dry_run is True

    def test_setup_tables_succeeds_in_dry_run(self, manager):
        result = manager.setup_tables()
        assert result is True

    def test_add_to_whitelist(self, manager):
        manager.add_to_whitelist("192.168.1.1")
        assert "192.168.1.1" in manager._whitelist

    def test_add_invalid_ip_to_whitelist(self, manager):
        manager.add_to_whitelist("not-an-ip")  # Should not raise
        assert "not-an-ip" not in manager._whitelist

    @pytest.mark.asyncio
    async def test_apply_action_allow_is_noop(self, manager):
        result = await manager.apply_action("1.2.3.4", action=0, threat_score=0.1)
        assert result is True
        assert len(manager.registry) == 0

    @pytest.mark.asyncio
    async def test_apply_action_drop_adds_rule(self, manager):
        result = await manager.apply_action("1.2.3.4", action=1, threat_score=0.95)
        assert result is True
        assert "1.2.3.4" in manager.registry
        rule = manager.registry.get("1.2.3.4")
        assert rule.action == "DROP"
        assert rule.threat_score == 0.95

    @pytest.mark.asyncio
    async def test_apply_action_rate_limit_adds_rule(self, manager):
        result = await manager.apply_action("5.6.7.8", action=2, threat_score=0.7)
        assert result is True
        assert "5.6.7.8" in manager.registry
        rule = manager.registry.get("5.6.7.8")
        assert rule.action == "RATE_LIMIT"

    @pytest.mark.asyncio
    async def test_whitelisted_ip_not_blocked(self, manager):
        manager.add_to_whitelist("10.0.0.1")
        result = await manager.apply_action("10.0.0.1", action=1, threat_score=0.99)
        assert result is True  # Returns True but applies no rule
        assert "10.0.0.1" not in manager.registry

    @pytest.mark.asyncio
    async def test_invalid_ip_rejected(self, manager):
        result = await manager.apply_action("not-valid-ip", action=1, threat_score=0.9)
        assert result is False

    @pytest.mark.asyncio
    async def test_duplicate_drop_refreshes_rule(self, manager):
        await manager.apply_action("9.9.9.9", action=1, threat_score=0.7)
        rule1_ttl = manager.registry.get("9.9.9.9").ttl_sec
        await manager.apply_action("9.9.9.9", action=1, threat_score=0.95)
        rule2_ttl = manager.registry.get("9.9.9.9").ttl_sec
        # TTL should be extended on refresh
        assert rule2_ttl >= rule1_ttl

    @pytest.mark.asyncio
    async def test_remove_rule(self, manager):
        await manager.apply_action("3.3.3.3", action=1, threat_score=0.8)
        assert "3.3.3.3" in manager.registry
        success = await manager.remove_rule("3.3.3.3")
        assert success is True
        assert "3.3.3.3" not in manager.registry

    @pytest.mark.asyncio
    async def test_remove_nonexistent_rule(self, manager):
        result = await manager.remove_rule("99.99.99.99")
        assert result is False

    @pytest.mark.asyncio
    async def test_capacity_limit_triggers_cleanup(self, config):
        """When max_rules is reached, emergency cleanup should free space."""
        config["nftables"]["max_rules"] = 3
        mgr = NftablesManager(config)
        # Fill to capacity
        for i in range(3):
            await mgr.apply_action(f"1.1.1.{i+1}", action=1, threat_score=float(i) / 10)
        initial_count = len(mgr.registry)
        # Adding one more should trigger emergency cleanup
        await mgr.apply_action("9.9.9.9", action=1, threat_score=0.95)
        # Registry count should be < initial_count + 1 due to cleanup
        assert len(mgr.registry) <= initial_count

    def test_list_rules_returns_list_of_dicts(self, manager):
        asyncio.get_event_loop().run_until_complete(
            manager.apply_action("7.7.7.7", action=1, threat_score=0.85)
        )
        rules = manager.list_rules()
        assert isinstance(rules, list)
        assert len(rules) == 1
        assert rules[0]["src_ip"] == "7.7.7.7"

    def test_get_stats_returns_dict(self, manager):
        stats = manager.get_stats()
        assert "active_rules" in stats
        assert "total_blocks" in stats
        assert "dry_run" in stats
        assert stats["dry_run"] is True

    def test_flush_all_rules(self, manager):
        asyncio.get_event_loop().run_until_complete(
            manager.apply_action("2.2.2.2", action=1, threat_score=0.9)
        )
        assert len(manager.registry) == 1
        manager.flush_all_rules()
        assert len(manager.registry) == 0
