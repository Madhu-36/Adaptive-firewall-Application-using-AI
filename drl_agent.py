"""
drl_agent.py
============
Deep Reinforcement Learning agent for adaptive firewall decisions.

Implements:
  - Custom Gymnasium Environment (FirewallEnv) modeling the network
    security state space and action consequences.
  - PPO agent via Stable-Baselines3 for policy optimization.
  - Self-healing loop that dynamically evaluates rule performance
    and auto-reverts false-positive triggers.

State Space (8 dimensions):
  [0] anomaly_score        - Current flow anomaly score [0, 1]
  [1] connection_rate       - Connections/sec from source IP (normalized)
  [2] packet_loss_rate      - Estimated packet loss ratio [0, 1]
  [3] false_positive_count  - Recent FP triggers (normalized)
  [4] active_rule_count     - Current kernel rules (normalized)
  [5] threat_class          - Predicted threat class (one-hot encoded summary)
  [6] flow_duration         - Current flow duration (normalized)
  [7] avg_latency           - Recent avg mitigation latency (normalized)

Action Space (Discrete, 4 actions):
  0: ALLOW / NO_ACTION
  1: DROP_IP
  2: RATE_LIMIT_IP
  3: REMOVE_RULE (self-healing cleanup)

Reward Function:
  +10 for blocking confirmed high-anomaly traffic (>0.85) within 50ms
  +5  bonus for sub-50ms response time
  -20 for blocking safe traffic (false positive)
  -5  for rule bloat (>MAX rules)
  +2  for cleaning up stale rules when threat subsides
"""

import logging
import time
from collections import deque
from typing import Any, Dict, Optional, Tuple

import gymnasium as gym
import numpy as np
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

import config

logger = logging.getLogger("firewall.drl")


# =============================================================================
# Custom Gymnasium Environment
# =============================================================================

class FirewallEnv(gym.Env):
    """
    Custom Gymnasium environment modeling the adaptive firewall's
    decision-making process.

    The environment simulates the consequences of firewall actions
    on network security state, incorporating realistic feedback loops.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, render_mode: Optional[str] = None):
        super().__init__()
        self.render_mode = render_mode

        # Observation: 8-dimensional continuous state
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(8,), dtype=np.float32
        )

        # Action: 4 discrete actions
        self.action_space = spaces.Discrete(config.NUM_ACTIONS)

        # Internal state tracking
        self._anomaly_score = 0.0
        self._connection_rate = 0.0
        self._packet_loss_rate = 0.0
        self._fp_count = 0
        self._active_rules = 0
        self._threat_class = 0.0
        self._flow_duration = 0.0
        self._avg_latency = 0.0

        # History for reward calculation
        self._fp_history = deque(maxlen=100)
        self._action_history = deque(maxlen=1000)
        self._step_count = 0
        self._episode_reward = 0.0

        # Synthetic traffic generator for training
        self._rng = np.random.default_rng(42)
        self._is_attack = False

    def reset(
        self, *, seed: Optional[int] = None, options: Optional[Dict] = None
    ) -> Tuple[np.ndarray, Dict]:
        """Reset the environment to an initial state."""
        super().reset(seed=seed)

        # Generate a new random network state
        self._is_attack = self._rng.random() > 0.65  # 35% chance of attack

        if self._is_attack:
            self._anomaly_score = float(self._rng.uniform(0.7, 1.0))
            self._connection_rate = float(self._rng.uniform(0.5, 1.0))
            self._packet_loss_rate = float(self._rng.uniform(0.1, 0.5))
            threat_types = [0.25, 0.5, 0.75, 1.0]  # Encoded threat classes
            self._threat_class = float(self._rng.choice(threat_types))
        else:
            self._anomaly_score = float(self._rng.uniform(0.0, 0.5))
            self._connection_rate = float(self._rng.uniform(0.0, 0.4))
            self._packet_loss_rate = float(self._rng.uniform(0.0, 0.05))
            self._threat_class = 0.0

        self._fp_count = len([x for x in self._fp_history if x])
        self._active_rules = int(self._rng.integers(0, 100))
        self._flow_duration = float(self._rng.uniform(0.0, 1.0))
        self._avg_latency = float(self._rng.uniform(0.0, 0.5))

        self._step_count = 0
        self._episode_reward = 0.0

        return self._get_obs(), {}

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """
        Execute one decision step.

        Args:
            action: 0=ALLOW, 1=DROP, 2=RATE_LIMIT, 3=REMOVE_RULE

        Returns:
            observation, reward, terminated, truncated, info
        """
        self._step_count += 1
        reward = 0.0
        info = {"action": action, "was_attack": self._is_attack}

        # Simulate mitigation latency
        latency_ms = float(self._rng.uniform(5, 80))
        info["latency_ms"] = latency_ms

        if action == config.ACTION_DROP:  # DROP_IP
            if self._is_attack and self._anomaly_score > config.ANOMALY_SCORE_THRESHOLD:
                # True positive: blocked confirmed threat
                reward += config.REWARD_TRUE_POSITIVE
                if latency_ms < config.MITIGATION_LATENCY_TARGET_MS:
                    reward += config.REWARD_FAST_RESPONSE
                self._active_rules += 1
                info["result"] = "TRUE_POSITIVE"
            elif not self._is_attack:
                # False positive: blocked safe traffic
                reward += config.PENALTY_FALSE_POSITIVE
                self._fp_history.append(True)
                self._fp_count += 1
                self._active_rules += 1
                info["result"] = "FALSE_POSITIVE"
            else:
                # Low-confidence block
                reward += config.REWARD_TRUE_POSITIVE * 0.3
                self._active_rules += 1
                info["result"] = "LOW_CONFIDENCE_BLOCK"

        elif action == config.ACTION_RATE_LIMIT:  # RATE_LIMIT_IP
            if self._is_attack:
                reward += config.REWARD_TRUE_POSITIVE * 0.5
                self._active_rules += 1
                info["result"] = "RATE_LIMITED_THREAT"
            else:
                reward += config.PENALTY_FALSE_POSITIVE * 0.3
                self._fp_history.append(True)
                info["result"] = "FALSE_RATE_LIMIT"

        elif action == config.ACTION_REMOVE_RULE:  # REMOVE_RULE (self-healing)
            if self._active_rules > 0 and not self._is_attack:
                # Good cleanup: removed a stale rule during safe period
                reward += config.REWARD_RULE_CLEANUP
                self._active_rules = max(0, self._active_rules - 1)
                info["result"] = "GOOD_CLEANUP"
            elif self._active_rules > 0 and self._is_attack:
                # Bad cleanup: removed rule during active attack
                reward += config.PENALTY_FALSE_POSITIVE * 0.5
                self._active_rules = max(0, self._active_rules - 1)
                info["result"] = "BAD_CLEANUP"
            else:
                reward -= 1.0  # No rules to remove
                info["result"] = "NO_RULES_TO_REMOVE"

        elif action == config.ACTION_ALLOW:  # ALLOW
            if self._is_attack and self._anomaly_score > config.ANOMALY_SCORE_THRESHOLD:
                # Missed a clear threat
                reward -= config.REWARD_TRUE_POSITIVE * 0.5
                info["result"] = "MISSED_THREAT"
            else:
                reward += 0.5  # Small reward for correctly allowing safe traffic
                self._fp_history.append(False)
                info["result"] = "CORRECT_ALLOW"

        # Penalize rule bloat
        normalized_rules = self._active_rules / config.MAX_KERNEL_RULES
        if normalized_rules > 0.8:
            reward += config.PENALTY_RULE_BLOAT

        self._action_history.append(action)
        self._episode_reward += reward

        # Evolve network state for next step
        self._evolve_state()

        # Episode ends after 200 steps
        terminated = self._step_count >= 200
        truncated = False

        return self._get_obs(), reward, terminated, truncated, info

    def _get_obs(self) -> np.ndarray:
        """Build the 8-dimensional observation vector."""
        return np.array([
            np.clip(self._anomaly_score, 0, 1),
            np.clip(self._connection_rate, 0, 1),
            np.clip(self._packet_loss_rate, 0, 1),
            np.clip(self._fp_count / 100.0, 0, 1),
            np.clip(self._active_rules / config.MAX_KERNEL_RULES, 0, 1),
            np.clip(self._threat_class, 0, 1),
            np.clip(self._flow_duration, 0, 1),
            np.clip(self._avg_latency, 0, 1),
        ], dtype=np.float32)

    def _evolve_state(self) -> None:
        """Simulate natural state evolution between steps."""
        # Randomly shift to new traffic pattern
        if self._rng.random() > 0.7:
            self._is_attack = self._rng.random() > 0.65

        if self._is_attack:
            self._anomaly_score = float(np.clip(
                self._anomaly_score + self._rng.uniform(-0.1, 0.2), 0, 1
            ))
            self._connection_rate = float(np.clip(
                self._connection_rate + self._rng.uniform(-0.05, 0.15), 0, 1
            ))
        else:
            self._anomaly_score = float(np.clip(
                self._anomaly_score + self._rng.uniform(-0.2, 0.05), 0, 1
            ))
            self._connection_rate = float(np.clip(
                self._connection_rate + self._rng.uniform(-0.1, 0.05), 0, 1
            ))

        self._flow_duration = float(np.clip(
            self._flow_duration + self._rng.uniform(-0.1, 0.1), 0, 1
        ))


# =============================================================================
# PPO Agent Wrapper
# =============================================================================

class TrainingCallback(BaseCallback):
    """Custom callback for logging during PPO training."""

    def __init__(self, log_interval: int = 5000, verbose: int = 0):
        super().__init__(verbose)
        self.log_interval = log_interval

    def _on_step(self) -> bool:
        if self.n_calls % self.log_interval == 0:
            logger.info(
                "PPO Training | Steps: %d | Mean reward: %.2f",
                self.n_calls,
                np.mean([ep["r"] for ep in self.model.ep_info_buffer]) if self.model.ep_info_buffer else 0.0,
            )
        return True


class FirewallPPOAgent:
    """
    PPO-based decision agent for the adaptive firewall.

    Wraps Stable-Baselines3 PPO with:
    - Training on the custom FirewallEnv
    - Inference for live decision-making
    - Self-healing loop for false-positive correction
    - Model persistence
    """

    def __init__(self):
        self.env = FirewallEnv()
        self.model: Optional[PPO] = None
        self._action_labels = {
            config.ACTION_ALLOW: "ALLOW",
            config.ACTION_DROP: "DROP_IP",
            config.ACTION_RATE_LIMIT: "RATE_LIMIT_IP",
            config.ACTION_REMOVE_RULE: "REMOVE_RULE",
        }
        # Self-healing tracker
        self._recent_decisions = deque(maxlen=200)
        self._fp_tracker: Dict[str, int] = {}  # IP -> consecutive FP count

    def train(self, total_timesteps: int = None) -> None:
        """
        Train the PPO agent on the FirewallEnv.
        """
        total_timesteps = total_timesteps or config.RL_TOTAL_TIMESTEPS
        logger.info("Training PPO agent for %d timesteps", total_timesteps)

        self.model = PPO(
            "MlpPolicy",
            self.env,
            learning_rate=config.RL_LEARNING_RATE,
            n_steps=config.RL_N_STEPS,
            batch_size=config.RL_BATCH_SIZE,
            n_epochs=config.RL_N_EPOCHS,
            gamma=config.RL_GAMMA,
            gae_lambda=config.RL_GAE_LAMBDA,
            clip_range=config.RL_CLIP_RANGE,
            verbose=0,
            device=config.INFERENCE_DEVICE,
        )

        callback = TrainingCallback(log_interval=10000)
        self.model.learn(
            total_timesteps=total_timesteps,
            callback=callback,
            progress_bar=True,
        )
        logger.info("PPO training complete")

    def decide(
        self,
        anomaly_score: float,
        connection_rate: float = 0.0,
        packet_loss_rate: float = 0.0,
        fp_count: int = 0,
        active_rules: int = 0,
        threat_class: float = 0.0,
        flow_duration: float = 0.0,
        avg_latency: float = 0.0,
        src_ip: str = "",
    ) -> Tuple[int, str]:
        """
        Make a firewall decision based on current network state.

        Returns:
            action:      Integer action code (0-3)
            action_name: Human-readable action name
        """
        if self.model is None:
            # Fallback: rule-based decision if no trained model
            return self._rule_based_fallback(anomaly_score, src_ip)

        obs = np.array([
            np.clip(anomaly_score, 0, 1),
            np.clip(connection_rate, 0, 1),
            np.clip(packet_loss_rate, 0, 1),
            np.clip(fp_count / 100.0, 0, 1),
            np.clip(active_rules / config.MAX_KERNEL_RULES, 0, 1),
            np.clip(threat_class, 0, 1),
            np.clip(flow_duration, 0, 1),
            np.clip(avg_latency, 0, 1),
        ], dtype=np.float32)

        action, _ = self.model.predict(obs, deterministic=True)
        action = int(action)
        action_name = self._action_labels.get(action, "UNKNOWN")

        # Self-healing check: override if IP has too many FPs
        action, action_name = self._self_healing_check(
            action, action_name, anomaly_score, src_ip
        )

        self._recent_decisions.append({
            "action": action,
            "anomaly_score": anomaly_score,
            "src_ip": src_ip,
            "timestamp": time.time(),
        })

        return action, action_name

    def _rule_based_fallback(
        self, anomaly_score: float, src_ip: str
    ) -> Tuple[int, str]:
        """
        Deterministic fallback when no RL model is loaded.
        Uses threshold-based rules.
        """
        if src_ip in config.WHITELIST_IPS:
            return config.ACTION_ALLOW, "ALLOW"
        if anomaly_score > config.ANOMALY_SCORE_THRESHOLD:
            return config.ACTION_DROP, "DROP_IP"
        if anomaly_score > config.RATE_LIMIT_THRESHOLD:
            return config.ACTION_RATE_LIMIT, "RATE_LIMIT_IP"
        return config.ACTION_ALLOW, "ALLOW"

    def _self_healing_check(
        self,
        action: int,
        action_name: str,
        anomaly_score: float,
        src_ip: str,
    ) -> Tuple[int, str]:
        """
        Self-healing loop: If an IP has been blocked multiple times
        with subsequently low anomaly scores, it's likely a false positive.
        Override the action to ALLOW and flag for rule removal.
        """
        if action in (config.ACTION_DROP, config.ACTION_RATE_LIMIT):
            # Check recent history for this IP
            recent_for_ip = [
                d for d in self._recent_decisions
                if d["src_ip"] == src_ip
                and d["action"] in (config.ACTION_DROP, config.ACTION_RATE_LIMIT)
            ]
            # If this IP was blocked before but current score is borderline
            if len(recent_for_ip) >= 2 and anomaly_score < config.RATE_LIMIT_THRESHOLD:
                logger.warning(
                    "Self-healing: IP %s was blocked %d times but current score %.3f "
                    "is below threshold. Overriding to ALLOW.",
                    src_ip, len(recent_for_ip), anomaly_score,
                )
                self._fp_tracker[src_ip] = self._fp_tracker.get(src_ip, 0) + 1
                return config.ACTION_REMOVE_RULE, "REMOVE_RULE"

        return action, action_name

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Save the trained PPO model to disk."""
        if self.model:
            from pathlib import Path
            Path(config.RL_MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
            self.model.save(config.RL_MODEL_PATH)
            logger.info("PPO model saved to %s", config.RL_MODEL_PATH)

    def load(self) -> bool:
        """Load a trained PPO model from disk."""
        try:
            self.model = PPO.load(config.RL_MODEL_PATH, env=self.env)
            logger.info("PPO model loaded from %s", config.RL_MODEL_PATH)
            return True
        except FileNotFoundError:
            logger.info("No saved PPO model found.")
            return False
        except Exception as e:
            logger.error("Error loading PPO model: %s", e)
            return False

    def get_self_healing_stats(self) -> Dict[str, Any]:
        """Return self-healing loop statistics."""
        return {
            "total_recent_decisions": len(self._recent_decisions),
            "fp_tracker": dict(self._fp_tracker),
            "recent_action_distribution": {
                self._action_labels.get(i, "?"): sum(
                    1 for d in self._recent_decisions if d["action"] == i
                )
                for i in range(config.NUM_ACTIONS)
            },
        }


# ---------------------------------------------------------------------------
# Standalone training script
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logger_db
    logger_db.setup_logging()

    agent = FirewallPPOAgent()
    agent.train(total_timesteps=100_000)
    agent.save()
    print("PPO agent trained and saved.")

    # Test inference
    action, name = agent.decide(
        anomaly_score=0.92, connection_rate=0.8,
        src_ip="192.168.1.100",
    )
    print(f"Decision: {name} (action={action})")
