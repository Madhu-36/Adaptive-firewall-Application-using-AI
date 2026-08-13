"""
rl/firewall_env.py
==================
Custom Gymnasium environment for the adaptive firewall PPO agent.

This environment wraps the real-time firewall decision problem:
  - The agent observes: flow features + anomaly score + system metrics
  - The agent takes actions: ALLOW / DROP / RATE_LIMIT
  - The agent receives rewards that balance security with availability

State Space (17 dimensions):
  [0-13]  Flow feature vector (14 dims from PacketEngine)
  [14]    Anomaly score (0.0 - 1.0)
  [15]    Active rule count (normalized to 0-1, max=1000)
  [16]    Current connection rate (normalized packets/sec)

Action Space (Discrete 3):
  0 = ALLOW      — let the flow through, no rule injected
  1 = DROP       — block source IP immediately via nftables
  2 = RATE_LIMIT — apply packet-per-second rate limit to source IP

Reward Function:
  True Positive  (attack detected, DROP/RATE_LIMIT): +10.0
  True Negative  (normal flow, ALLOW):               +1.0
  False Positive (normal flow, DROP):                -5.0
  False Positive (normal flow, RATE_LIMIT):          -2.0
  False Negative (attack, ALLOW):                    -8.0
  Rule Bloat     (per active rule beyond 100):       -0.01 per step
  Latency Bonus  (response < 50ms):                  +0.5
"""

import logging
from typing import Any, Dict, Optional, Tuple

import numpy as np
import gymnasium as gym
from gymnasium import spaces

logger = logging.getLogger(__name__)

OBS_DIM = 17          # 14 flow features + anomaly_score + rule_count + conn_rate
N_ACTIONS = 3         # 0=ALLOW, 1=DROP, 2=RATE_LIMIT
ACTION_NAMES = ["ALLOW", "DROP", "RATE_LIMIT"]


class FirewallEnv(gym.Env):
    """
    Gymnasium-compatible firewall environment.

    In production, this env is driven by the live feature queue.
    For training, it uses a synthetic traffic generator.
    """

    metadata = {"render_modes": ["human", "ansi"]}

    def __init__(
        self,
        config: Optional[dict] = None,
        mode: str = "train",           # "train" | "live"
        feature_queue=None,            # asyncio.Queue from PacketEngine (live mode)
        rule_registry=None,            # RuleRegistry from nftables_manager (live mode)
    ):
        super().__init__()
        self.config = config or {}
        self.mode = mode
        self.feature_queue = feature_queue
        self.rule_registry = rule_registry

        # ── Observation Space ────────────────────────────────────────────────
        # All values bounded [0, 1] after normalization
        self.observation_space = spaces.Box(
            low=np.zeros(OBS_DIM, dtype=np.float32),
            high=np.ones(OBS_DIM, dtype=np.float32),
            dtype=np.float32,
        )

        # ── Action Space ─────────────────────────────────────────────────────
        self.action_space = spaces.Discrete(N_ACTIONS)

        # ── Episode state ────────────────────────────────────────────────────
        self._current_obs: Optional[np.ndarray] = None
        self._current_metadata: Optional[dict] = None
        self._step_count = 0
        self._episode_reward = 0.0
        self._max_steps = self.config.get("rl", {}).get("max_steps_per_episode", 1000)

        # Synthetic traffic generator state
        self._rng = np.random.default_rng(42)
        self._active_rules: int = 0
        self._connection_rate: float = 0.0

        # Statistics
        self._stats = {
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "total_drops": 0,
            "total_allows": 0,
            "total_rate_limits": 0,
        }

    # ------------------------------------------------------------------
    # Gymnasium interface
    # ------------------------------------------------------------------

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[dict] = None,
    ) -> Tuple[np.ndarray, dict]:
        """Reset the environment to the start of a new episode."""
        super().reset(seed=seed)
        if seed is not None:
            self._rng = np.random.default_rng(seed)

        self._step_count = 0
        self._episode_reward = 0.0
        self._active_rules = 0
        self._connection_rate = float(self._rng.uniform(10, 500))

        obs, metadata = self._generate_observation()
        self._current_obs = obs
        self._current_metadata = metadata

        return obs, {"metadata": metadata}

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, dict]:
        """
        Apply action to the current flow and compute reward.

        Args:
            action: 0=ALLOW, 1=DROP, 2=RATE_LIMIT

        Returns:
            obs:        Next observation
            reward:     Float reward
            terminated: Whether episode ended (goal reached)
            truncated:  Whether episode was cut short (max steps)
            info:       Additional info dict
        """
        assert self._current_obs is not None, "Call reset() before step()"

        # Ground truth from metadata (training mode only)
        is_attack = self._current_metadata.get("is_attack", False)
        anomaly_score = float(self._current_obs[14])

        # ── Compute Reward ────────────────────────────────────────────────────
        reward = self._compute_reward(action, is_attack, anomaly_score)

        # ── Update system state ───────────────────────────────────────────────
        if action == 1:  # DROP
            self._active_rules = min(self._active_rules + 1, 1000)
            self._stats["total_drops"] += 1
        elif action == 2:  # RATE_LIMIT
            self._active_rules = min(self._active_rules + 1, 1000)
            self._stats["total_rate_limits"] += 1
        else:  # ALLOW
            self._stats["total_allows"] += 1

        # Simulate rule expiry (some rules auto-expire each step)
        if self._active_rules > 0 and self._rng.random() < 0.05:
            self._active_rules = max(0, self._active_rules - 1)

        # ── Next observation ──────────────────────────────────────────────────
        obs, metadata = self._generate_observation()
        self._current_obs = obs
        self._current_metadata = metadata

        self._step_count += 1
        self._episode_reward += reward

        truncated = self._step_count >= self._max_steps
        terminated = False  # No terminal state in this env; only truncation

        info = {
            "action_name": ACTION_NAMES[action],
            "is_attack": is_attack,
            "anomaly_score": anomaly_score,
            "active_rules": self._active_rules,
            "episode_reward": self._episode_reward,
            "stats": self._stats.copy(),
        }

        return obs, reward, terminated, truncated, info

    def render(self, mode: str = "human") -> Optional[str]:
        """Render the current state to console."""
        obs = self._current_obs
        meta = self._current_metadata
        if obs is None:
            return None
        line = (
            f"Step {self._step_count:4d} | "
            f"Anomaly={obs[14]:.3f} | "
            f"Rules={self._active_rules:4d} | "
            f"ConnRate={obs[16]:.3f} | "
            f"Attack={meta.get('is_attack', '?')} | "
            f"EpReward={self._episode_reward:.2f}"
        )
        if mode == "human":
            print(line)
        return line

    # ------------------------------------------------------------------
    # Reward shaping
    # ------------------------------------------------------------------

    def _compute_reward(
        self,
        action: int,
        is_attack: bool,
        anomaly_score: float,
    ) -> float:
        """Compute the reward signal with security/availability trade-off."""
        reward = 0.0

        if is_attack:
            if action == 1:    # True Positive — correctly blocked
                reward += 10.0
                self._stats["true_positives"] += 1
            elif action == 2:  # Partially correct — rate limited an attack
                reward += 4.0
                self._stats["true_positives"] += 1
            else:              # False Negative — attack allowed through
                reward -= 8.0
                self._stats["false_negatives"] += 1
        else:
            if action == 0:    # True Negative — correctly allowed
                reward += 1.0
                self._stats["true_negatives"] += 1
            elif action == 1:  # False Positive (hard) — legit user blocked
                reward -= 5.0
                self._stats["false_positives"] += 1
            elif action == 2:  # False Positive (soft) — legit user throttled
                reward -= 2.0
                self._stats["false_positives"] += 1

        # Rule bloat penalty — discourage excessive rule accumulation
        if self._active_rules > 100:
            reward -= 0.01 * (self._active_rules - 100)

        # High confidence reward bonus
        if is_attack and anomaly_score > 0.8 and action == 1:
            reward += 2.0  # Bonus for high-confidence correct block

        return float(reward)

    # ------------------------------------------------------------------
    # Observation generation
    # ------------------------------------------------------------------

    def _generate_observation(self) -> Tuple[np.ndarray, dict]:
        """
        Generate a synthetic observation for training.
        Simulates a realistic mix of normal and attack traffic.
        """
        is_attack = self._rng.random() < 0.15  # 15% attack rate

        if is_attack:
            # Attack patterns: high pkt_count, low IAT, high syn_ratio
            raw_features = np.array([
                self._rng.uniform(0.5, 1.0),     # src_ip (normalized)
                self._rng.uniform(0.0, 0.1),     # dst_ip (server)
                self._rng.uniform(0.1, 1.0),     # src_port
                self._rng.choice([0.001, 0.001, 0.006, 0.019]),  # common dst_ports
                0.006 / 65535,                   # TCP protocol
                self._rng.uniform(0.5, 1.0),     # pkt_count (high, normalized)
                self._rng.uniform(0.5, 1.0),     # byte_count
                self._rng.uniform(0.0, 0.1),     # avg_pkt_size (small = SYN)
                self._rng.uniform(0.0, 0.05),    # std_pkt_size
                self._rng.uniform(0.0, 0.01),    # min_iat (very fast)
                self._rng.uniform(0.0, 0.05),    # max_iat
                self._rng.uniform(0.0, 0.02),    # avg_iat
                self._rng.uniform(0.0, 0.3),     # flow_duration
                self._rng.uniform(0.7, 1.0),     # syn_ratio (high)
            ], dtype=np.float32)
            anomaly_score = float(self._rng.uniform(0.65, 1.0))
        else:
            # Normal patterns: moderate pkt_count, varied IAT, low syn_ratio
            raw_features = np.array([
                self._rng.uniform(0.0, 0.5),     # src_ip
                self._rng.uniform(0.0, 0.1),     # dst_ip
                self._rng.uniform(0.0, 0.3),     # src_port
                self._rng.choice([0.001, 0.006]),  # http/https
                0.006 / 65535,                   # TCP
                self._rng.uniform(0.0, 0.2),     # pkt_count (low)
                self._rng.uniform(0.1, 0.6),     # byte_count
                self._rng.uniform(0.2, 0.8),     # avg_pkt_size (normal)
                self._rng.uniform(0.05, 0.3),    # std_pkt_size
                self._rng.uniform(0.05, 0.5),    # min_iat
                self._rng.uniform(0.1, 1.0),     # max_iat
                self._rng.uniform(0.1, 0.5),     # avg_iat
                self._rng.uniform(0.1, 0.9),     # flow_duration
                self._rng.uniform(0.0, 0.1),     # syn_ratio (low)
            ], dtype=np.float32)
            anomaly_score = float(self._rng.uniform(0.0, 0.4))

        # Connection rate drifts over time
        self._connection_rate += self._rng.uniform(-50, 50)
        self._connection_rate = np.clip(self._connection_rate, 0, 10000)
        conn_rate_norm = float(self._connection_rate / 10000.0)

        # Rule count (normalized)
        rule_count_norm = float(self._active_rules / 1000.0)

        obs = np.concatenate([
            np.clip(raw_features, 0.0, 1.0),
            [anomaly_score, rule_count_norm, conn_rate_norm],
        ]).astype(np.float32)

        metadata = {
            "is_attack": is_attack,
            "anomaly_score": anomaly_score,
            "src_ip": f"10.{int(obs[0]*255)}.{int(obs[1]*255)}.{int(obs[2]*255+1)}",
        }

        return obs, metadata

    # ------------------------------------------------------------------
    # Live mode: feed from real PacketEngine
    # ------------------------------------------------------------------

    def set_live_observation(
        self,
        feature_vec: np.ndarray,
        anomaly_score: float,
        metadata: dict,
    ) -> None:
        """
        Inject a real flow observation into the environment (live mode).
        Called by the main pipeline when the ML model scores a real flow.
        """
        if self.rule_registry is not None:
            active_rules = len(self.rule_registry)
        else:
            active_rules = self._active_rules

        rule_count_norm = float(min(active_rules, 1000) / 1000.0)
        conn_rate_norm = float(min(self._connection_rate, 10000) / 10000.0)

        # Normalize raw features to [0, 1] range
        norm_features = np.clip(feature_vec / (np.abs(feature_vec).max() + 1e-8), 0.0, 1.0)

        obs = np.concatenate([
            norm_features[:14],
            [anomaly_score, rule_count_norm, conn_rate_norm],
        ]).astype(np.float32)

        self._current_obs = obs
        self._current_metadata = metadata

    def get_current_observation(self) -> Optional[np.ndarray]:
        """Return current observation for the live pipeline."""
        return self._current_obs

    def get_stats(self) -> dict:
        """Return environment statistics."""
        total = sum(self._stats[k] for k in ["true_positives", "true_negatives",
                                              "false_positives", "false_negatives"])
        tp = self._stats["true_positives"]
        fp = self._stats["false_positives"]
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + self._stats["false_negatives"], 1)
        return {
            **self._stats,
            "total_decisions": total,
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / max(precision + recall, 1e-8),
        }
