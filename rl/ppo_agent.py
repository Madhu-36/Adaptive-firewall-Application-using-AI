"""
rl/ppo_agent.py
===============
Proximal Policy Optimization (PPO) agent for autonomous firewall policy learning.

This module integrates Stable-Baselines3's PPO implementation with our custom
FirewallEnv to train a neural network policy that learns the optimal balance
between security (blocking attacks) and availability (allowing legitimate traffic).

PPO Hyperparameters:
  n_steps:       2048   — steps per rollout buffer
  batch_size:    64     — minibatch size for gradient updates
  n_epochs:      10     — number of optimization epochs per rollout
  learning_rate: 3e-4   — Adam optimizer learning rate
  clip_range:    0.2    — PPO clipping parameter epsilon
  ent_coef:      0.01   — entropy coefficient for exploration
  vf_coef:       0.5    — value function loss coefficient
  gamma:         0.99   — discount factor
  gae_lambda:    0.95   — GAE lambda

Policy Network:
  MLP with [256, 256] hidden layers (actor and critic share same architecture)
"""

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import yaml

logger = logging.getLogger(__name__)

ACTION_NAMES = {0: "ALLOW", 1: "DROP", 2: "RATE_LIMIT"}


class PPOFirewallAgent:
    """
    Wrapper around Stable-Baselines3 PPO for the firewall use case.

    Handles:
    - Training from scratch or loading a pre-trained model
    - Online inference (< 5ms per decision)
    - Periodic model checkpointing
    - Logging and metrics collection
    """

    def __init__(self, config: dict, env=None):
        self.config = config
        rl_cfg = config.get("rl", {})
        self.model_path = rl_cfg.get("model_path", "models/ppo_firewall.zip")
        self.total_timesteps = rl_cfg.get("total_timesteps", 500_000)
        self.save_every = rl_cfg.get("save_every_n_steps", 10_000)
        self.train_on_startup = rl_cfg.get("train_on_startup", False)

        self.env = env  # FirewallEnv instance
        self._model = None  # SB3 PPO model
        self._trained = False

        # Decision statistics
        self._decision_counts = {0: 0, 1: 0, 2: 0}
        self._total_decisions = 0
        self._inference_times: List[float] = []

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def initialize(self, env=None) -> None:
        """
        Initialize the PPO model. Must be called before train() or predict().
        Attempts to load a saved model first; trains from scratch if not found.
        """
        from stable_baselines3 import PPO
        from stable_baselines3.common.callbacks import CheckpointCallback
        from stable_baselines3.common.monitor import Monitor

        if env is not None:
            self.env = env

        if self.env is None:
            # Create default training environment
            from rl.firewall_env import FirewallEnv
            self.env = FirewallEnv(self.config, mode="train")

        # Wrap with SB3 Monitor for logging
        monitored_env = Monitor(self.env)

        if not self.load():
            logger.info("Initializing fresh PPO model...")
            self._model = PPO(
                policy="MlpPolicy",
                env=monitored_env,
                # ── PPO Hyperparameters ──────────────────────────────────
                learning_rate=3e-4,
                n_steps=2048,
                batch_size=64,
                n_epochs=10,
                gamma=0.99,
                gae_lambda=0.95,
                clip_range=0.2,
                clip_range_vf=None,         # No value function clipping
                normalize_advantage=True,
                ent_coef=0.01,              # Entropy for exploration
                vf_coef=0.5,
                max_grad_norm=0.5,
                # ── Policy Network Architecture ───────────────────────────
                policy_kwargs=dict(
                    net_arch=[dict(pi=[256, 256], vf=[256, 256])],
                    activation_fn=__import__('torch.nn', fromlist=['Tanh']).Tanh,
                ),
                verbose=1,
                tensorboard_log="logs/ppo_tensorboard/",
                device="cpu",
            )
            logger.info("PPO model initialized with MLP([256, 256]) architecture")
        else:
            # Update env on loaded model
            self._model.set_env(monitored_env)

    def train(self, total_timesteps: Optional[int] = None) -> None:
        """
        Train the PPO agent.

        Args:
            total_timesteps: Override the config value if provided.
        """
        if self._model is None:
            self.initialize()

        from stable_baselines3.common.callbacks import CheckpointCallback, EvalCallback

        timesteps = total_timesteps or self.total_timesteps
        logger.info("Starting PPO training for %d timesteps...", timesteps)

        # Checkpoint every N steps
        checkpoint_cb = CheckpointCallback(
            save_freq=self.save_every,
            save_path="models/checkpoints/",
            name_prefix="ppo_firewall",
            verbose=0,
        )

        start_time = time.time()
        self._model.learn(
            total_timesteps=timesteps,
            callback=checkpoint_cb,
            reset_num_timesteps=not self._trained,
            progress_bar=True,
        )
        elapsed = time.time() - start_time
        logger.info("Training complete in %.1f seconds. Saving model...", elapsed)

        self.save()
        self._trained = True

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, observation: np.ndarray, deterministic: bool = True) -> Tuple[int, dict]:
        """
        Predict the optimal action for the given observation.

        Args:
            observation:   Shape (17,) — current firewall state observation
            deterministic: If True, takes argmax; if False, samples from policy

        Returns:
            action:  0=ALLOW, 1=DROP, 2=RATE_LIMIT
            info:    Dict with action probabilities and inference time
        """
        if self._model is None:
            logger.warning("PPO model not initialized. Using rule-based fallback.")
            return self._rule_based_fallback(observation)

        start_t = time.perf_counter()

        action, _states = self._model.predict(
            observation,
            deterministic=deterministic,
        )

        elapsed_ms = (time.perf_counter() - start_t) * 1000
        self._inference_times.append(elapsed_ms)
        if len(self._inference_times) > 1000:
            self._inference_times = self._inference_times[-1000:]  # Rolling window

        action = int(action)
        self._decision_counts[action] += 1
        self._total_decisions += 1

        logger.debug(
            "PPO decision: %s | latency: %.2fms | anomaly_score: %.3f",
            ACTION_NAMES[action],
            elapsed_ms,
            float(observation[14]) if len(observation) > 14 else 0.0,
        )

        info = {
            "action_name": ACTION_NAMES[action],
            "inference_ms": elapsed_ms,
            "decision_counts": self._decision_counts.copy(),
        }

        return action, info

    def _rule_based_fallback(
        self, observation: np.ndarray
    ) -> Tuple[int, dict]:
        """
        Simple threshold-based fallback when PPO model is not available.
        Used during initialization or when model loading fails.
        """
        anomaly_score = float(observation[14]) if len(observation) > 14 else 0.0

        if anomaly_score > 0.8:
            action = 1   # DROP — high confidence anomaly
        elif anomaly_score > 0.5:
            action = 2   # RATE_LIMIT — moderate anomaly
        else:
            action = 0   # ALLOW — likely normal

        return action, {"action_name": ACTION_NAMES[action], "fallback": True}

    # ------------------------------------------------------------------
    # Async inference loop (live pipeline)
    # ------------------------------------------------------------------

    async def run_inference_loop(
        self,
        feature_queue: asyncio.Queue,
        action_queue: asyncio.Queue,
        behavior_classifier,
        firewall_env,
    ) -> None:
        """
        Main async inference loop for the live firewall pipeline.

        Reads flow features from feature_queue, scores them with the ML classifier,
        feeds the state to PPO, and pushes (action, metadata) to action_queue.

        Target latency: < 50ms from feature arrival to action output.
        """
        logger.info("PPO inference loop started")
        loop_count = 0

        while True:
            try:
                # Wait for next flow feature vector (timeout prevents blocking forever)
                feature_vec, metadata = await asyncio.wait_for(
                    feature_queue.get(),
                    timeout=5.0,
                )

                t_start = time.perf_counter()

                # ── Step 1: ML Anomaly Score ──────────────────────────────────
                anomaly_score, is_anomaly, latent_vec = behavior_classifier.predict(feature_vec)

                # ── Step 2: Build RL Observation ──────────────────────────────
                firewall_env.set_live_observation(feature_vec, anomaly_score, metadata)
                obs = firewall_env.get_current_observation()

                # ── Step 3: PPO Decision ──────────────────────────────────────
                action, action_info = self.predict(obs, deterministic=True)

                t_elapsed_ms = (time.perf_counter() - t_start) * 1000

                # Compile decision packet
                decision = {
                    "action": action,
                    "action_name": ACTION_NAMES[action],
                    "src_ip": metadata.get("src_ip", "unknown"),
                    "dst_ip": metadata.get("dst_ip", "unknown"),
                    "src_port": metadata.get("src_port", 0),
                    "dst_port": metadata.get("dst_port", 0),
                    "protocol": metadata.get("protocol", 0),
                    "anomaly_score": anomaly_score,
                    "is_anomaly": is_anomaly,
                    "total_latency_ms": t_elapsed_ms,
                    "timestamp": time.time(),
                }

                try:
                    action_queue.put_nowait(decision)
                except asyncio.QueueFull:
                    logger.warning("Action queue full — dropping decision for %s",
                                   metadata.get("src_ip"))

                loop_count += 1
                if loop_count % 100 == 0:
                    avg_lat = np.mean(self._inference_times[-100:]) if self._inference_times else 0
                    logger.info(
                        "Inference loop: %d decisions | avg_latency=%.2fms | "
                        "ALLOW=%d DROP=%d RATE_LIMIT=%d",
                        loop_count,
                        avg_lat,
                        self._decision_counts[0],
                        self._decision_counts[1],
                        self._decision_counts[2],
                    )

                # Warn if latency target exceeded
                if t_elapsed_ms > 50:
                    logger.warning(
                        "Latency target exceeded: %.2fms > 50ms for flow %s",
                        t_elapsed_ms,
                        metadata.get("src_ip"),
                    )

            except asyncio.TimeoutError:
                # No packets for 5 seconds — normal during low-traffic periods
                continue
            except Exception as e:
                logger.error("Inference loop error: %s", e, exc_info=True)
                await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Save PPO model weights to disk."""
        if self._model is None:
            logger.warning("No model to save.")
            return
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
        self._model.save(self.model_path)
        logger.info("PPO model saved to %s", self.model_path)

    def load(self) -> bool:
        """Load PPO model from disk. Returns True on success."""
        from stable_baselines3 import PPO

        model_file = self.model_path
        if not model_file.endswith(".zip"):
            model_file += ".zip"

        if not Path(model_file).exists():
            logger.info("No saved PPO model at %s", model_file)
            return False

        try:
            self._model = PPO.load(self.model_path, device="cpu")
            self._trained = True
            logger.info("Loaded PPO model from %s", self.model_path)
            return True
        except Exception as e:
            logger.error("Error loading PPO model: %s", e)
            return False

    def get_stats(self) -> dict:
        """Return agent performance statistics."""
        avg_lat = float(np.mean(self._inference_times)) if self._inference_times else 0.0
        p99_lat = float(np.percentile(self._inference_times, 99)) if len(self._inference_times) > 10 else 0.0
        return {
            "trained": self._trained,
            "total_decisions": self._total_decisions,
            "decision_counts": self._decision_counts.copy(),
            "avg_inference_ms": avg_lat,
            "p99_inference_ms": p99_lat,
        }


# ---------------------------------------------------------------------------
# Module entry-point for standalone training
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import yaml
    logging.basicConfig(level=logging.INFO)

    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)

    from rl.firewall_env import FirewallEnv

    env = FirewallEnv(cfg, mode="train")
    agent = PPOFirewallAgent(cfg, env=env)
    agent.initialize()

    print("Training PPO agent for 100,000 timesteps...")
    agent.train(total_timesteps=100_000)

    # Test inference
    obs, _ = env.reset()
    action, info = agent.predict(obs)
    print(f"Test action: {info['action_name']} | Inference: {info['inference_ms']:.2f}ms")
