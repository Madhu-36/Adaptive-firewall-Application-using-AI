"""
tests/test_packet_engine.py
============================
Unit tests for the PacketEngine and FlowTable modules.
"""

import asyncio
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from sniffer.packet_engine import FlowKey, FlowRecord, FlowTable, PacketEngine

# ---------------------------------------------------------------------------
# Configuration fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def config():
    return {
        "firewall": {"interface": "lo", "simulation_mode": True, "promiscuous_mode": True},
        "flow": {"idle_timeout_sec": 5, "max_concurrent_flows": 100, "feature_queue_maxsize": 500},
        "ml": {"anomaly_threshold": 0.65},
    }


# ---------------------------------------------------------------------------
# FlowRecord tests
# ---------------------------------------------------------------------------

class TestFlowRecord:
    def test_initial_state(self):
        record = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol=6)
        assert record.pkt_count == 0
        assert record.byte_count == 0
        assert record.syn_count == 0

    def test_update_increments_counts(self):
        record = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol=6)
        record.update(pkt_size=100, is_syn=True)
        record.update(pkt_size=200, is_syn=False)
        assert record.pkt_count == 2
        assert record.byte_count == 300
        assert record.syn_count == 1
        assert len(record.pkt_sizes) == 2

    def test_inter_arrival_times_populated_after_two_packets(self):
        record = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol=6)
        record.update(100)
        time.sleep(0.01)  # 10ms
        record.update(100)
        assert len(record.inter_arrival_times) == 1
        assert record.inter_arrival_times[0] >= 0.005  # at least 5ms

    def test_to_feature_vector_shape(self):
        record = FlowRecord(src_ip="10.0.0.1", dst_ip="192.168.1.1", src_port=4321, dst_port=443, protocol=6)
        for _ in range(10):
            record.update(pkt_size=np.random.randint(40, 1500), is_syn=False)
        vec = record.to_feature_vector()
        assert vec.shape == (14,), f"Expected shape (14,), got {vec.shape}"
        assert vec.dtype == np.float32

    def test_feature_vector_syn_ratio(self):
        record = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=0, dst_port=80, protocol=6)
        for _ in range(8):
            record.update(40, is_syn=True)
        for _ in range(2):
            record.update(40, is_syn=False)
        vec = record.to_feature_vector()
        # syn_flag_ratio is at index 13
        assert abs(vec[13] - 0.8) < 0.01, f"Expected syn_ratio=0.8, got {vec[13]}"

    def test_feature_vector_ip_encoding(self):
        record = FlowRecord(src_ip="0.0.0.0", dst_ip="255.255.255.255", src_port=0, dst_port=0, protocol=0)
        record.update(100)
        record.update(100)
        vec = record.to_feature_vector()
        assert vec[0] == 0.0          # 0.0.0.0 = 0
        assert vec[1] == float(0xFFFFFFFF)   # 255.255.255.255 = max u32

    def test_invalid_ip_fallback(self):
        record = FlowRecord(src_ip="not-an-ip", dst_ip="also-not-an-ip", src_port=0, dst_port=0, protocol=0)
        record.update(100)
        record.update(100)
        vec = record.to_feature_vector()
        assert vec[0] == 0.0
        assert vec[1] == 0.0


# ---------------------------------------------------------------------------
# FlowTable tests
# ---------------------------------------------------------------------------

class TestFlowTable:
    def test_update_or_create_adds_flow(self):
        table = FlowTable(max_flows=100, idle_timeout=60)
        key: FlowKey = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        table.update_or_create(key, pkt_size=100)
        assert table.active_count == 1

    def test_same_flow_accumulates(self):
        table = FlowTable(max_flows=100, idle_timeout=60)
        key: FlowKey = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        table.update_or_create(key, pkt_size=100)
        table.update_or_create(key, pkt_size=200)
        assert table.active_count == 1
        with table._lock:
            record = table._table[key]
        assert record.pkt_count == 2
        assert record.byte_count == 300

    def test_different_flows_create_separate_entries(self):
        table = FlowTable(max_flows=100, idle_timeout=60)
        key1: FlowKey = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        key2: FlowKey = ("3.3.3.3", "4.4.4.4", 5678, 443, 6)
        table.update_or_create(key1, 100)
        table.update_or_create(key2, 200)
        assert table.active_count == 2

    def test_max_flows_evicts_oldest(self):
        table = FlowTable(max_flows=3, idle_timeout=60)
        for i in range(5):
            key: FlowKey = (f"1.1.1.{i+1}", "2.2.2.2", i, 80, 6)
            table.update_or_create(key, 100)
        assert table.active_count == 3  # never exceeds max

    def test_collect_expired_returns_idle_flows(self):
        table = FlowTable(max_flows=100, idle_timeout=0.01)  # 10ms timeout
        key: FlowKey = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        table.update_or_create(key, 100)
        table.update_or_create(key, 100)  # 2 packets
        time.sleep(0.05)  # Wait for expiry
        expired = table.collect_expired()
        assert len(expired) == 1
        assert expired[0][0] == key
        assert table.active_count == 0

    def test_collect_expired_skips_active_flows(self):
        table = FlowTable(max_flows=100, idle_timeout=60)
        key: FlowKey = ("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        table.update_or_create(key, 100)
        table.update_or_create(key, 100)
        expired = table.collect_expired()
        assert len(expired) == 0

    def test_thread_safety_concurrent_updates(self):
        """Stress test: multiple threads updating the flow table concurrently."""
        import threading
        table = FlowTable(max_flows=1000, idle_timeout=60)
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    key: FlowKey = (f"10.0.{thread_id}.{i % 256}", "192.168.1.1", i, 80, 6)
                    table.update_or_create(key, 100)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"


# ---------------------------------------------------------------------------
# PacketEngine tests
# ---------------------------------------------------------------------------

class TestPacketEngine:
    @pytest.mark.asyncio
    async def test_simulation_mode_produces_vectors(self, config):
        """PacketEngine in simulation mode should produce feature vectors."""
        engine = PacketEngine(config)
        await engine.start()

        # Wait for at least 3 vectors to be produced
        vectors = []
        for _ in range(30):  # up to 3 seconds
            await asyncio.sleep(0.1)
            while not engine.feature_queue.empty():
                vec, meta = engine.feature_queue.get_nowait()
                vectors.append((vec, meta))
            if len(vectors) >= 3:
                break

        await engine.stop()

        assert len(vectors) >= 1, "Expected at least 1 feature vector from simulation"
        vec, meta = vectors[0]
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (14,)
        assert vec.dtype == np.float32
        assert "src_ip" in meta
        assert "dst_ip" in meta

    @pytest.mark.asyncio
    async def test_get_stats_returns_dict(self, config):
        engine = PacketEngine(config)
        await engine.start()
        await asyncio.sleep(0.1)
        stats = engine.get_stats()
        await engine.stop()

        assert isinstance(stats, dict)
        assert "packets_captured" in stats
        assert "active_flows" in stats
        assert "simulation_mode" in stats
        assert stats["simulation_mode"] is True

    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self, config):
        engine = PacketEngine(config)
        await engine.start()
        await engine.stop()
        await engine.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_feature_queue_respects_maxsize(self, config):
        """Queue should not exceed maxsize even under load."""
        config["flow"]["feature_queue_maxsize"] = 5
        engine = PacketEngine(config)
        await engine.start()
        await asyncio.sleep(0.5)  # Let producer generate flows
        await engine.stop()
        # Queue should never exceed maxsize
        assert engine.feature_queue.qsize() <= 5
