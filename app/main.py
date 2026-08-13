"""
app/main.py
===========
FastAPI application — Administrative API and Real-Time Dashboard backend.

Endpoints:
  GET  /api/stats           — Full system metrics snapshot
  GET  /api/rules           — List all active firewall rules
  GET  /api/engine-stats    — PacketEngine + ML + PPO stats
  POST /api/allow/{ip}      — Manually whitelist an IP
  POST /api/block/{ip}      — Manually block an IP
  POST /api/flush           — Emergency: remove all rules
  GET  /api/health          — Health check endpoint
  WS   /ws/events           — Real-time event stream (block/allow events)
  GET  /                    — Serve dashboard.html

WebSocket Event Format:
  {
    "type": "block_event" | "allow_event" | "stats_update",
    "timestamp": 1720000000.0,
    "src_ip": "1.2.3.4",
    "action": "DROP" | "ALLOW" | "RATE_LIMIT",
    "anomaly_score": 0.93,
    "total_latency_ms": 12.4,
    "kernel_latency_ms": 3.1,
    "active_rules": 42
  }
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Internal modules ────────────────────────────────────────────────────────────
import sys
import random

class MockPacketEngine:
    def __init__(self, config, feature_queue):
        self.feature_queue = feature_queue
        self.running = False
        class MockFlowTable:
            active_count = 0
        self.flow_table = MockFlowTable()
    async def start(self):
        self.running = True
        asyncio.create_task(self._simulation())
    async def stop(self):
        self.running = False
    async def _simulation(self):
        while self.running:
            await asyncio.sleep(0.5)
            # mock features
            await self.feature_queue.put(([0]*14, {"src_ip": "192.168.1.100", "dst_ip": "1.1.1.1", "src_port": 12345, "dst_port": 443, "protocol": 6}))
    def get_stats(self): return {"status": "mocked", "msg": "Using Mock Packet Engine"}

class MockBehaviorClassifier:
    def __init__(self, config): pass
    def load(self): return True
    def get_stats(self): return {"status": "mocked", "msg": "ML disabled on Windows"}
    def save(self): pass
    def train_unsupervised(self, data, epochs): pass
    async def predict(self, features): return 0.0

class MockFirewallEnv:
    def __init__(self, config, mode): pass

class MockPPOFirewallAgent:
    def __init__(self, config): self._model = "Mock"
    def initialize(self, env): pass
    async def run_inference_loop(self, feature_queue, action_queue, classifier, env):
        while True:
            item = await feature_queue.get()
            if not isinstance(item, tuple) or len(item) != 2: continue
            features, meta = item
            # Allow everything in mock mode, randomly drop some
            action = "DROP" if random.random() < 0.1 else "ALLOW"
            await action_queue.put({"action_name": action, "anomaly_score": random.random(), "src_ip": meta.get("src_ip", "unknown")})
    def train(self): pass
    def get_stats(self): return {"status": "mocked", "msg": "RL disabled on Windows"}

class MockNftablesManager:
    def __init__(self, config): self.registry = {}
    def setup_tables(self): pass
    async def start_cleanup_loop(self):
        while True: await asyncio.sleep(3600)
    def stop(self): pass
    def list_rules(self): return []
    def flush_all_rules(self): return True
    def get_stats(self): return {"status": "mocked", "msg": "nftables disabled on Windows"}
    async def process_action_queue(self, action_queue, broadcast_cb):
        while True:
            decision = await action_queue.get()
            await broadcast_cb(decision)

try:
    from sniffer.packet_engine import PacketEngine
    from models.behavior_classifier import BehaviorClassifier
    from rl.firewall_env import FirewallEnv
    from rl.ppo_agent import PPOFirewallAgent
    from kernel.nftables_manager import NftablesManager
except ImportError:
    PacketEngine = MockPacketEngine
    BehaviorClassifier = MockBehaviorClassifier
    FirewallEnv = MockFirewallEnv
    PPOFirewallAgent = MockPPOFirewallAgent
    NftablesManager = MockNftablesManager


logger = logging.getLogger(__name__)

# =============================================================================
# Load Configuration
# =============================================================================

def load_config(path: str = "config/settings.yaml") -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("settings.yaml not found — using defaults")
        return {
            "firewall": {"interface": "eth0", "simulation_mode": True},
            "flow": {"idle_timeout_sec": 60, "max_concurrent_flows": 50000, "feature_queue_maxsize": 10000},
            "ml": {"anomaly_threshold": 0.65, "batch_size": 32, "inference_device": "cpu",
                   "model_path": "models/behavior_classifier.pt", "scaler_path": "models/scaler.pkl"},
            "rl": {"model_path": "models/ppo_firewall.zip", "train_on_startup": False, "total_timesteps": 500000},
            "nftables": {"enabled": False, "rule_ttl_sec": 300, "cleanup_interval_sec": 30,
                         "max_rules": 1000, "rate_limit_pps": 100},
            "api": {"host": "0.0.0.0", "port": 8000,
                    "cors_origins": ["http://localhost:3000", "http://localhost:8000"]},
        }


config = load_config()

# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Adaptive Firewall AI",
    description="Next-Generation Adaptive Firewall: Real-Time Anomaly Detection and Kernel-Level Rule Automation",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("api", {}).get("cors_origins", ["*"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (dashboard)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# =============================================================================
# Global Pipeline Components (initialized on startup)
# =============================================================================

packet_engine: Optional[PacketEngine] = None
behavior_classifier: Optional[BehaviorClassifier] = None
firewall_env: Optional[FirewallEnv] = None
ppo_agent: Optional[PPOFirewallAgent] = None
nftables_manager: Optional[NftablesManager] = None

# Queues connecting the pipeline stages
feature_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
action_queue: asyncio.Queue = asyncio.Queue(maxsize=5_000)

# WebSocket connection manager
class ConnectionManager:
    """Manages active WebSocket connections for broadcasting events."""

    def __init__(self):
        self.active: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.active.add(ws)
        logger.info("WebSocket connected. Total connections: %d", len(self.active))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.active.discard(ws)
        logger.info("WebSocket disconnected. Total connections: %d", len(self.active))

    async def broadcast(self, data: dict) -> None:
        """Broadcast an event to all connected WebSocket clients."""
        if not self.active:
            return
        message = json.dumps(data)
        dead = set()
        for ws in list(self.active):
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        async with self._lock:
            self.active -= dead


manager = ConnectionManager()

# Running stats (in-memory)
_stats = {
    "total_flows_processed": 0,
    "total_blocks": 0,
    "total_allows": 0,
    "total_rate_limits": 0,
    "false_positives_estimate": 0,
    "avg_latency_ms": 0.0,
    "uptime_start": time.time(),
    "recent_latencies": [],  # Rolling window of last 100 latencies
}

# =============================================================================
# Startup & Shutdown
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize all pipeline components on FastAPI startup."""
    global packet_engine, behavior_classifier, firewall_env, ppo_agent, nftables_manager

    logger.info("=" * 60)
    logger.info("Adaptive Firewall AI — Starting up")
    logger.info("=" * 60)

    # ── 1. Packet Engine ────────────────────────────────────────────────────────
    packet_engine = PacketEngine(config, feature_queue=feature_queue)
    await packet_engine.start()

    # ── 2. ML Behavior Classifier ───────────────────────────────────────────────
    behavior_classifier = BehaviorClassifier(config)
    if not behavior_classifier.load():
        logger.info("Training ML model on synthetic data...")
        import numpy as np
        rng = np.random.default_rng(42)
        normal_data = rng.standard_normal((5000, 14)).astype('float32')
        behavior_classifier.train_unsupervised(normal_data, epochs=20)
        behavior_classifier.save()

    # ── 3. Firewall Environment + PPO Agent ───────────────────────────────────
    firewall_env = FirewallEnv(config, mode="live")
    ppo_agent = PPOFirewallAgent(config)
    ppo_agent.initialize(env=FirewallEnv(config, mode="train"))

    if config.get("rl", {}).get("train_on_startup", False):
        logger.info("Training PPO agent on startup (this may take a while)...")
        asyncio.create_task(asyncio.to_thread(ppo_agent.train))

    # ── 4. nftables Manager ─────────────────────────────────────────────────────
    nftables_manager = NftablesManager(config)
    nftables_manager.setup_tables()
    asyncio.create_task(nftables_manager.start_cleanup_loop())

    # ── 5. Start pipeline tasks ─────────────────────────────────────────────────
    asyncio.create_task(
        ppo_agent.run_inference_loop(
            feature_queue, action_queue, behavior_classifier, firewall_env
        )
    )
    asyncio.create_task(
        nftables_manager.process_action_queue(action_queue, _broadcast_event)
    )
    asyncio.create_task(_periodic_stats_broadcast())

    logger.info("All pipeline components initialized and running.")


@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown."""
    if packet_engine:
        await packet_engine.stop()
    if nftables_manager:
        nftables_manager.stop()
    logger.info("Adaptive Firewall AI — Shutdown complete")


# =============================================================================
# Event Broadcasting
# =============================================================================

async def _broadcast_event(decision: dict) -> None:
    """Called by the action queue processor to broadcast decisions to dashboards."""
    action_name = decision.get("action_name", "UNKNOWN")
    anomaly_score = decision.get("anomaly_score", 0.0)

    # Update in-memory stats
    _stats["total_flows_processed"] += 1
    if action_name == "DROP":
        _stats["total_blocks"] += 1
    elif action_name == "RATE_LIMIT":
        _stats["total_rate_limits"] += 1
    else:
        _stats["total_allows"] += 1

    lat = decision.get("total_latency_ms", 0)
    _stats["recent_latencies"].append(lat)
    if len(_stats["recent_latencies"]) > 100:
        _stats["recent_latencies"] = _stats["recent_latencies"][-100:]
    _stats["avg_latency_ms"] = sum(_stats["recent_latencies"]) / len(_stats["recent_latencies"])

    event = {
        "type": "block_event" if action_name in ("DROP", "RATE_LIMIT") else "allow_event",
        "timestamp": time.time(),
        "src_ip": decision.get("src_ip", "unknown"),
        "dst_ip": decision.get("dst_ip", "unknown"),
        "action": action_name,
        "anomaly_score": round(anomaly_score, 4),
        "total_latency_ms": round(lat, 2),
        "kernel_latency_ms": round(decision.get("kernel_latency_ms", 0), 2),
        "active_rules": len(nftables_manager.registry) if nftables_manager else 0,
    }
    await manager.broadcast(event)


async def _periodic_stats_broadcast() -> None:
    """Broadcast system stats every 2 seconds to all WebSocket clients."""
    while True:
        await asyncio.sleep(2.0)
        try:
            stats_event = {
                "type": "stats_update",
                "timestamp": time.time(),
                "uptime_sec": round(time.time() - _stats["uptime_start"], 1),
                "total_flows": _stats["total_flows_processed"],
                "total_blocks": _stats["total_blocks"],
                "total_allows": _stats["total_allows"],
                "total_rate_limits": _stats["total_rate_limits"],
                "avg_latency_ms": round(_stats["avg_latency_ms"], 2),
                "active_rules": len(nftables_manager.registry) if nftables_manager else 0,
                "active_flows": packet_engine.flow_table.active_count if packet_engine else 0,
            }
            await manager.broadcast(stats_event)
        except Exception as e:
            logger.debug("Stats broadcast error: %s", e)


# =============================================================================
# REST API Endpoints
# =============================================================================

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the live dashboard HTML."""
    dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return HTMLResponse("<h1>Dashboard not found</h1><p>Place dashboard.html in app/static/</p>")


@app.get("/api/health")
async def health_check():
    """Basic health check."""
    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _stats["uptime_start"], 1),
        "components": {
            "packet_engine": packet_engine is not None,
            "ml_classifier": behavior_classifier is not None,
            "ppo_agent": ppo_agent is not None and ppo_agent._model is not None,
            "nftables": nftables_manager is not None,
        },
    }


@app.get("/api/stats")
async def get_stats():
    """Comprehensive system statistics."""
    engine_stats = packet_engine.get_stats() if packet_engine else {}
    ml_stats = behavior_classifier.get_stats() if behavior_classifier else {}
    agent_stats = ppo_agent.get_stats() if ppo_agent else {}
    kernel_stats = nftables_manager.get_stats() if nftables_manager else {}

    return {
        "pipeline": {
            "total_flows_processed": _stats["total_flows_processed"],
            "total_blocks": _stats["total_blocks"],
            "total_allows": _stats["total_allows"],
            "total_rate_limits": _stats["total_rate_limits"],
            "avg_latency_ms": round(_stats["avg_latency_ms"], 3),
        },
        "packet_engine": engine_stats,
        "ml_classifier": ml_stats,
        "ppo_agent": agent_stats,
        "kernel": kernel_stats,
        "uptime_sec": round(time.time() - _stats["uptime_start"], 1),
    }


@app.get("/api/rules")
async def get_active_rules():
    """List all active firewall rules."""
    if nftables_manager is None:
        return {"rules": [], "count": 0}
    rules = nftables_manager.list_rules()
    return {"rules": rules, "count": len(rules)}


@app.post("/api/allow/{ip}")
async def whitelist_ip(ip: str):
    """Manually whitelist an IP (prevent it from ever being blocked)."""
    if nftables_manager is None:
        raise HTTPException(status_code=503, detail="nftables manager not initialized")
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")

    nftables_manager.add_to_whitelist(ip)
    # Also remove any existing block rule for this IP
    if ip in nftables_manager.registry:
        await nftables_manager.remove_rule(ip)

    return {"status": "whitelisted", "ip": ip}


@app.post("/api/block/{ip}")
async def manual_block_ip(ip: str):
    """Manually block an IP address."""
    if nftables_manager is None:
        raise HTTPException(status_code=503, detail="nftables manager not initialized")
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")

    success = await nftables_manager.apply_action(ip, action=1, threat_score=1.0)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to apply block rule")
    return {"status": "blocked", "ip": ip}


@app.post("/api/flush")
async def flush_all_rules():
    """Emergency: remove all firewall rules."""
    if nftables_manager is None:
        raise HTTPException(status_code=503, detail="nftables manager not initialized")
    success = nftables_manager.flush_all_rules()
    return {"status": "flushed" if success else "failed", "rules_removed": _stats["total_blocks"]}


# =============================================================================
# WebSocket Endpoint
# =============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.

    The client receives:
    - block_event / allow_event: per-flow decisions with latency
    - stats_update: system-wide metrics every 2 seconds
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; server pushes events via broadcast
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            # Handle ping/pong or client commands
            try:
                cmd = json.loads(data)
                if cmd.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "timestamp": time.time()}))
            except json.JSONDecodeError:
                pass
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        await manager.disconnect(websocket)


# =============================================================================
# Entry point for uvicorn
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    api_cfg = config.get("api", {})
    uvicorn.run(
        "app.main:app",
        host=api_cfg.get("host", "0.0.0.0"),
        port=api_cfg.get("port", 8000),
        reload=False,
        workers=1,
        log_level="info",
    )
