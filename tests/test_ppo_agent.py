"""
tests/test_ppo_agent.py
========================
Unit tests for the FirewallEnv Gymnasium environment and PPOFirewallAgent.
"""

import numpy as np
import pytest

from rl.firewall_env import FirewallEnv, OBS_DIM, N_ACTIONS, ACTION_NAMES
from rl.ppo_agent import PPOFirewallAgent


@pytest.fixture
def config():
    return {
        "firewall": {"simulation_mode": True},
        "rl": {
            "model_path": "/tmp/test_ppo.zip",
            "train_on_startup": False,
            "total_timesteps": 1000,
            "save_every_n_steps": 500,
            "max_steps_per_episode": 100,
        },
        "nftables": {"max_rules": 1000},
    }


@pytest.fixture
def env(config):
    return FirewallEnv(config, mode="train")


# ---------------------------------------------------------------------------
# FirewallEnv tests
# ---------------------------------------------------------------------------

class TestFirewallEnv:
    def test_observation_space_shape(self, env):
        assert env.observation_space.shape == (OBS_DIM,)

    def test_action_space(self, env):
        assert env.action_space.n == N_ACTIONS

    def test_reset_returns_valid_obs(self, env):
        obs, info = env.reset(seed=42)
        assert obs.shape == (OBS_DIM,)
        assert obs.dtype == np.float32
        assert (obs >= 0.0).all() and (obs <= 1.0).all(), "Observation out of [0,1] bounds"
        assert "metadata" in info

    def test_step_returns_correct_types(self, env):
        env.reset(seed=0)
        obs, reward, terminated, truncated, info = env.step(0)
        assert isinstance(obs, np.ndarray)
        assert isinstance(reward, float)
        assert isinstance(terminated, bool)
        assert isinstance(truncated, bool)
        assert isinstance(info, dict)

    def test_step_all_actions(self, env):
        for action in range(N_ACTIONS):
            env.reset(seed=action)
            obs, reward, _, _, info = env.step(action)
            assert obs.shape == (OBS_DIM,)
            assert info["action_name"] == ACTION_NAMES[action]

    def test_true_positive_reward(self, env):
        """Correctly blocking an attack should give positive reward."""
        env.reset(seed=10)
        # Inject a known attack observation
        env._current_metadata = {"is_attack": True, "anomaly_score": 0.95}
        env._current_obs = np.ones(OBS_DIM, dtype=np.float32) * 0.5
        env._current_obs[14] = 0.95  # High anomaly score
        _, reward, _, _, _ = env.step(1)  # DROP action
        assert reward > 0, f"True positive reward should be positive, got {reward}"

    def test_false_positive_penalty(self, env):
        """Blocking normal traffic should give negative reward."""
        env.reset(seed=20)
        env._current_metadata = {"is_attack": False, "anomaly_score": 0.1}
        env._current_obs = np.ones(OBS_DIM, dtype=np.float32) * 0.1
        _, reward, _, _, _ = env.step(1)  # DROP on normal traffic
        assert reward < 0, f"False positive penalty should be negative, got {reward}"

    def test_false_negative_penalty(self, env):
        """Allowing an attack should give large negative reward."""
        env.reset(seed=30)
        env._current_metadata = {"is_attack": True, "anomaly_score": 0.9}
        env._current_obs = np.ones(OBS_DIM, dtype=np.float32) * 0.5
        env._current_obs[14] = 0.9
        _, reward, _, _, _ = env.step(0)  # ALLOW on attack
        assert reward < 0, f"False negative should give negative reward, got {reward}"

    def test_episode_truncates_at_max_steps(self, config):
        config["rl"]["max_steps_per_episode"] = 5
        env = FirewallEnv(config, mode="train")
        env.reset(seed=0)
        truncated = False
        for _ in range(10):
            _, _, terminated, truncated, _ = env.step(0)
            if truncated:
                break
        assert truncated, "Episode should truncate after max_steps"

    def test_get_stats_returns_dict(self, env):
        env.reset()
        env.step(0)
        env.step(1)
        stats = env.get_stats()
        assert "total_decisions" in stats
        assert "precision" in stats
        assert "recall" in stats
        assert "f1" in stats

    def test_set_live_observation(self, env):
        feature_vec = np.random.randn(14).astype(np.float32)
        env.set_live_observation(feature_vec, anomaly_score=0.75, metadata={"src_ip": "1.2.3.4"})
        obs = env.get_current_observation()
        assert obs is not None
        assert obs.shape == (OBS_DIM,)
        assert abs(obs[14] - 0.75) < 0.001  # anomaly score preserved

    def test_render_returns_string(self, env):
        env.reset()
        env.step(0)
        result = env.render(mode="ansi")
        assert isinstance(result, str)
        assert "Step" in result


# ---------------------------------------------------------------------------
# PPOFirewallAgent tests
# ---------------------------------------------------------------------------

class TestPPOFirewallAgent:
    def test_rule_based_fallback_high_anomaly(self, config):
        agent = PPOFirewallAgent(config)
        obs = np.zeros(17, dtype=np.float32)
        obs[14] = 0.95  # Very high anomaly
        action, info = agent._rule_based_fallback(obs)
        assert action == 1, f"High anomaly should trigger DROP, got {ACTION_NAMES[action]}"

    def test_rule_based_fallback_medium_anomaly(self, config):
        agent = PPOFirewallAgent(config)
        obs = np.zeros(17, dtype=np.float32)
        obs[14] = 0.65  # Medium anomaly
        action, info = agent._rule_based_fallback(obs)
        assert action == 2, f"Medium anomaly should trigger RATE_LIMIT, got {ACTION_NAMES[action]}"

    def test_rule_based_fallback_low_anomaly(self, config):
        agent = PPOFirewallAgent(config)
        obs = np.zeros(17, dtype=np.float32)
        obs[14] = 0.1  # Low anomaly
        action, info = agent._rule_based_fallback(obs)
        assert action == 0, f"Low anomaly should ALLOW, got {ACTION_NAMES[action]}"

    def test_predict_without_model_uses_fallback(self, config):
        """When no model is loaded, predict() should use rule-based fallback."""
        agent = PPOFirewallAgent(config)
        obs = np.zeros(17, dtype=np.float32)
        obs[14] = 0.9
        action, info = agent.predict(obs)
        assert action in (0, 1, 2), f"Invalid action: {action}"
        assert info.get("fallback") is True

    def test_initialize_creates_model(self, config, env):
        """initialize() should create an SB3 PPO model."""
        agent = PPOFirewallAgent(config, env=env)
        agent.initialize()
        assert agent._model is not None

    def test_train_short_run(self, config, env):
        """Training for a small number of steps should complete without error."""
        agent = PPOFirewallAgent(config, env=env)
        agent.initialize()
        agent.train(total_timesteps=512)  # Very short training
        assert agent._trained is True

    def test_predict_with_trained_model(self, config, env):
        """After training, predict() should return valid actions."""
        agent = PPOFirewallAgent(config, env=env)
        agent.initialize()
        agent.train(total_timesteps=512)
        obs, _ = env.reset()
        action, info = agent.predict(obs, deterministic=True)
        assert action in (0, 1, 2)
        assert "action_name" in info
        assert "inference_ms" in info
        assert info["inference_ms"] < 100, f"Inference too slow: {info['inference_ms']}ms"

    def test_get_stats(self, config, env):
        agent = PPOFirewallAgent(config, env=env)
        agent.initialize()
        obs, _ = env.reset()
        agent.predict(obs)
        stats = agent.get_stats()
        assert "total_decisions" in stats
        assert stats["total_decisions"] >= 1
        assert "avg_inference_ms" in stats
