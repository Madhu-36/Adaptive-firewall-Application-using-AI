"""
main.py
=======
Master orchestrator for the Next-Generation Adaptive Firewall.

Launches and coordinates all subsystems concurrently:
  1. PacketSniffer    - Live packet capture & feature extraction
  2. AnomalyClassifier - ML-based anomaly detection
  3. FirewallPPOAgent  - Deep RL decision engine
  4. KernelEnforcer    - nftables rule injection
  5. DatabaseManager   - Event logging & audit trail
  6. Flask Dashboard   - Real-time web monitoring

Pipeline:
  Sniffer -> feature_queue -> Classifier -> decision -> RL Agent -> action_queue -> Kernel Enforcer
                                                                                       |
                                                                                  DB Logger
                                                                                       |
                                                                                  Dashboard
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time
from typing import Optional

import numpy as np

import config
from app_dashboard import create_dashboard_app
from classifier import AnomalyClassifier
from drl_agent import FirewallPPOAgent
from kernel_enforcer import KernelEnforcer
from logger_db import DatabaseManager, setup_logging
from sniffer import PacketSniffer


logger = logging.getLogger("firewall.main")


class FirewallOrchestrator:
    """
    Central orchestrator that manages the lifecycle of all firewall
    subsystems and coordinates the data pipeline.
    """

    def __init__(self):
        # Initialize logging
        setup_logging()
        logger.info("="*60)
        logger.info("NEXT-GENERATION ADAPTIVE FIREWALL")
        logger.info("Real-Time Anomaly Detection & Kernel-Level Rule Automation")
        logger.info("="*60)
        logger.info("Simulation mode: %s", config.SIMULATION_MODE)
        logger.info("Interface: %s", config.NETWORK_INTERFACE)

        # Shared queues
        self.feature_queue: asyncio.Queue = asyncio.Queue(
            maxsize=config.FEATURE_QUEUE_MAXSIZE
        )
        self.action_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)

        # Initialize subsystems
        self.db = DatabaseManager()
        self.sniffer = PacketSniffer(feature_queue=self.feature_queue)
        self.classifier = AnomalyClassifier()
        self.rl_agent = FirewallPPOAgent()
        self.enforcer = KernelEnforcer()

        # Running state
        self._running = False
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _initialize_models(self) -> None:
        """Load or train ML and RL models."""
        logger.info("Initializing ML models...")

        # Try loading saved models
        if not self.classifier.load():
            logger.info("Training classifier from scratch with mock data...")
            X_normal, X_attack, y_attack, X_all = self.classifier.generate_mock_data()
            self.classifier.train_autoencoder(X_normal, epochs=30)
            y_all = np.concatenate([
                np.zeros(len(X_normal), dtype=np.int64), y_attack
            ])
            self.classifier.fine_tune_classifier(X_all, y_all, epochs=20)
            self.classifier.save()

        if not self.rl_agent.load():
            logger.info("Training RL agent from scratch...")
            self.rl_agent.train(total_timesteps=50_000)  # Quick train for startup
            self.rl_agent.save()

        logger.info("All models initialized.")

    def _initialize_kernel(self) -> None:
        """Setup nftables tables and chains."""
        logger.info("Initializing kernel enforcement...")
        self.enforcer.setup_tables()

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    async def _classifier_loop(self) -> None:
        """
        Stage 2: Pull feature vectors from the sniffer queue,
        run ML inference, and feed decisions to the RL agent.
        """
        logger.info("Classifier loop started")
        while self._running:
            try:
                flow_info = await asyncio.wait_for(
                    self.feature_queue.get(), timeout=2.0
                )

                features = flow_info["features"]
                src_ip = flow_info["src_ip"]

                # ML inference
                anomaly_score, threat_label, latent_vec = self.classifier.predict(features)

                # RL decision
                action, action_name = self.rl_agent.decide(
                    anomaly_score=anomaly_score,
                    connection_rate=min(features[5] / 1000.0, 1.0),  # pkt_count normalized
                    threat_class=anomaly_score,  # Use score as proxy
                    flow_duration=min(features[12] / 60.0, 1.0),
                    active_rules=len(self.enforcer.registry),
                    src_ip=src_ip,
                )

                # Queue the decision for kernel enforcement
                decision = {
                    "src_ip": src_ip,
                    "action": action,
                    "action_name": action_name,
                    "anomaly_score": anomaly_score,
                    "threat_type": threat_label,
                    "timestamp": time.time(),
                }

                try:
                    self.action_queue.put_nowait(decision)
                except asyncio.QueueFull:
                    logger.warning("Action queue full")

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Classifier loop error: %s", e, exc_info=True)
                await asyncio.sleep(0.1)

    async def _enforcer_loop(self) -> None:
        """
        Stage 3: Pull decisions from the action queue and apply
        kernel-level rules via nftables.
        """
        logger.info("Kernel enforcer loop started")
        while self._running:
            try:
                decision = await asyncio.wait_for(
                    self.action_queue.get(), timeout=2.0
                )

                action_name = decision["action_name"]
                src_ip = decision["src_ip"]
                anomaly_score = decision["anomaly_score"]
                threat_type = decision["threat_type"]

                # Apply kernel action and measure latency
                latency_ms = await self.enforcer.apply_action(
                    src_ip=src_ip,
                    action_name=action_name,
                    threat_type=threat_type,
                    anomaly_score=anomaly_score,
                )

                # Log to database
                self.db.log_event(
                    source_ip=src_ip,
                    threat_type=threat_type,
                    anomaly_score=anomaly_score,
                    action_taken=action_name,
                    mitigation_latency_ms=latency_ms,
                    rule_status="ACTIVE" if action_name in ("DROP_IP", "RATE_LIMIT_IP") else "N/A",
                )

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Enforcer loop error: %s", e, exc_info=True)
                await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def _start_dashboard(self) -> None:
        """Launch the Flask dashboard in a separate thread."""
        app = create_dashboard_app(
            db_manager=self.db,
            kernel_enforcer=self.enforcer,
            classifier=self.classifier,
            sniffer=self.sniffer,
        )

        def run_flask():
            logger.info(
                "Dashboard starting at http://%s:%d",
                config.DASHBOARD_HOST, config.DASHBOARD_PORT,
            )
            app.run(
                host=config.DASHBOARD_HOST,
                port=config.DASHBOARD_PORT,
                debug=False,
                use_reloader=False,
            )

        flask_thread = threading.Thread(target=run_flask, daemon=True, name="dashboard")
        flask_thread.start()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main async entry point. Starts all subsystems and runs until
        shutdown signal is received.
        """
        self._running = True

        # Initialize models and kernel
        self._initialize_models()
        self._initialize_kernel()

        # Start database writer
        self.db.start()

        # Start dashboard in background thread
        self._start_dashboard()

        # Start async pipeline tasks
        tasks = [
            asyncio.create_task(self.sniffer.start()),
            asyncio.create_task(self._classifier_loop()),
            asyncio.create_task(self._enforcer_loop()),
            asyncio.create_task(self.enforcer.start_cleanup_loop()),
        ]

        logger.info("")
        logger.info("=" * 60)
        logger.info("  FIREWALL ACTIVE - All systems operational")
        logger.info("  Dashboard: http://%s:%d", config.DASHBOARD_HOST, config.DASHBOARD_PORT)
        logger.info("  Mode: %s", "SIMULATION" if config.SIMULATION_MODE else "LIVE")
        logger.info("=" * 60)
        logger.info("")

        # Wait for shutdown
        try:
            await self._shutdown_event.wait()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            await self._shutdown(tasks)

    async def _shutdown(self, tasks) -> None:
        """Graceful shutdown of all subsystems."""
        logger.info("Shutting down firewall...")
        self._running = False

        await self.sniffer.stop()
        self.enforcer.stop()
        self.db.stop()

        for task in tasks:
            task.cancel()

        logger.info("Firewall shutdown complete.")


def main():
    """Entry point."""
    # Enable simulation mode on Windows
    if sys.platform == "win32" or os.name == "nt":
        os.environ.setdefault("FW_SIMULATION", "true")
        # Reload config to pick up the env var
        import importlib
        importlib.reload(config)

    orchestrator = FirewallOrchestrator()

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logger.info("Received signal %s, shutting down...", sig)
        orchestrator._shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # Run the orchestrator
    asyncio.run(orchestrator.run())


if __name__ == "__main__":
    main()
