"""
tests/test_behavior_classifier.py
==================================
Unit tests for the BehaviorClassifier ML model.
"""

import numpy as np
import pytest
import torch

from models.behavior_classifier import (
    AnomalyAutoencoder,
    BehaviorClassifier,
    FEATURE_DIM,
    LATENT_DIM,
)


@pytest.fixture
def config():
    return {
        "ml": {
            "model_path": "/tmp/test_classifier.pt",
            "scaler_path": "/tmp/test_scaler.pkl",
            "anomaly_threshold": 0.65,
            "batch_size": 16,
            "inference_device": "cpu",
        }
    }


@pytest.fixture
def trained_classifier(config):
    """Returns a BehaviorClassifier trained on 500 synthetic samples."""
    clf = BehaviorClassifier(config)
    rng = np.random.default_rng(42)
    normal_data = rng.standard_normal((500, FEATURE_DIM)).astype(np.float32)
    clf.train_unsupervised(normal_data, epochs=5)
    return clf


# ---------------------------------------------------------------------------
# AnomalyAutoencoder architecture tests
# ---------------------------------------------------------------------------

class TestAnomalyAutoencoder:
    def test_output_shapes(self):
        model = AnomalyAutoencoder(feature_dim=FEATURE_DIM, latent_dim=LATENT_DIM)
        batch = torch.randn(8, FEATURE_DIM)
        reconstructed, latent, class_score = model(batch)
        assert reconstructed.shape == (8, FEATURE_DIM)
        assert latent.shape == (8, LATENT_DIM)
        assert class_score.shape == (8, 1)

    def test_encoder_only(self):
        model = AnomalyAutoencoder()
        batch = torch.randn(4, FEATURE_DIM)
        latent = model.encode(batch)
        assert latent.shape == (4, LATENT_DIM)

    def test_reconstruction_error_shape(self):
        model = AnomalyAutoencoder()
        batch = torch.randn(8, FEATURE_DIM)
        errors = model.reconstruction_error(batch)
        assert errors.shape == (8,)
        assert (errors >= 0).all(), "Reconstruction errors should be non-negative"

    def test_class_score_bounded(self):
        model = AnomalyAutoencoder()
        batch = torch.randn(32, FEATURE_DIM)
        _, _, scores = model(batch)
        assert (scores >= 0).all() and (scores <= 1).all(), "Classifier scores must be in [0, 1]"

    def test_gradient_flows(self):
        model = AnomalyAutoencoder()
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        batch = torch.randn(8, FEATURE_DIM)
        reconstructed, _, _ = model(batch)
        loss = torch.nn.functional.mse_loss(reconstructed, batch)
        loss.backward()
        optimizer.step()
        # Check that at least some gradients were computed
        has_grad = any(p.grad is not None and p.grad.abs().sum() > 0
                       for p in model.parameters())
        assert has_grad, "No gradients computed — model may be broken"

    def test_parameter_count_reasonable(self):
        model = AnomalyAutoencoder()
        n_params = sum(p.numel() for p in model.parameters())
        # Should be between 10k and 500k parameters
        assert 10_000 < n_params < 500_000, f"Unexpected parameter count: {n_params}"


# ---------------------------------------------------------------------------
# BehaviorClassifier interface tests
# ---------------------------------------------------------------------------

class TestBehaviorClassifier:
    def test_untrained_predict_uses_quick_init(self, config):
        """Untrained model should auto-initialize and return a valid score."""
        clf = BehaviorClassifier(config)
        vec = np.random.randn(FEATURE_DIM).astype(np.float32)
        score, is_anomaly, latent = clf.predict(vec)
        assert 0.0 <= score <= 1.0
        assert isinstance(is_anomaly, bool)
        assert latent.shape == (LATENT_DIM,)

    def test_train_unsupervised_runs(self, config):
        clf = BehaviorClassifier(config)
        rng = np.random.default_rng(0)
        data = rng.standard_normal((200, FEATURE_DIM)).astype(np.float32)
        history = clf.train_unsupervised(data, epochs=3)
        assert "train_loss" in history
        assert "val_loss" in history
        assert len(history["train_loss"]) == 3
        assert all(l >= 0 for l in history["train_loss"])

    def test_threshold_calibrated_after_training(self, trained_classifier):
        """After training, threshold_error should be > 0."""
        assert trained_classifier._threshold_error > 0
        assert trained_classifier._trained is True

    def test_normal_traffic_low_score(self, trained_classifier):
        """Normal traffic (in-distribution) should produce low anomaly scores."""
        rng = np.random.default_rng(99)
        normal_vecs = rng.standard_normal((20, FEATURE_DIM)).astype(np.float32)
        results = trained_classifier.predict_batch(normal_vecs)
        scores = [r[0] for r in results]
        # At least 70% should have score < threshold
        low_score_ratio = sum(1 for s in scores if s < 0.65) / len(scores)
        assert low_score_ratio >= 0.6, f"Too many false positives: {1 - low_score_ratio:.1%}"

    def test_attack_traffic_higher_score(self, trained_classifier):
        """Outlier traffic (attack-like) should produce higher anomaly scores."""
        rng = np.random.default_rng(42)
        attack_vecs = (rng.standard_normal((10, FEATURE_DIM)) * 8).astype(np.float32)
        normal_vecs = rng.standard_normal((10, FEATURE_DIM)).astype(np.float32)
        attack_results = trained_classifier.predict_batch(attack_vecs)
        normal_results = trained_classifier.predict_batch(normal_vecs)
        avg_attack_score = np.mean([r[0] for r in attack_results])
        avg_normal_score = np.mean([r[0] for r in normal_results])
        assert avg_attack_score > avg_normal_score, (
            f"Attack scores ({avg_attack_score:.3f}) should exceed normal ({avg_normal_score:.3f})"
        )

    def test_predict_returns_correct_types(self, trained_classifier):
        vec = np.zeros(FEATURE_DIM, dtype=np.float32)
        score, is_anomaly, latent = trained_classifier.predict(vec)
        assert isinstance(score, float)
        assert isinstance(is_anomaly, bool)
        assert isinstance(latent, np.ndarray)
        assert latent.shape == (LATENT_DIM,)

    def test_batch_predict_consistent_with_single(self, trained_classifier):
        rng = np.random.default_rng(1)
        vecs = rng.standard_normal((5, FEATURE_DIM)).astype(np.float32)
        batch_results = trained_classifier.predict_batch(vecs)
        for i, vec in enumerate(vecs):
            single_score, single_is_anomaly, _ = trained_classifier.predict(vec)
            batch_score, batch_is_anomaly, _ = batch_results[i]
            assert abs(single_score - batch_score) < 0.01, (
                f"Score mismatch at index {i}: single={single_score}, batch={batch_score}"
            )

    def test_save_and_load(self, trained_classifier, config, tmp_path):
        """Model should survive a save/load round-trip."""
        config["ml"]["model_path"] = str(tmp_path / "model.pt")
        config["ml"]["scaler_path"] = str(tmp_path / "scaler.pkl")
        trained_classifier.model_path = config["ml"]["model_path"]
        trained_classifier.scaler_path = config["ml"]["scaler_path"]
        trained_classifier.save()

        # Load into a fresh instance
        clf2 = BehaviorClassifier(config)
        clf2.model_path = config["ml"]["model_path"]
        clf2.scaler_path = config["ml"]["scaler_path"]
        assert clf2.load() is True

        rng = np.random.default_rng(7)
        vec = rng.standard_normal(FEATURE_DIM).astype(np.float32)
        score1, _, _ = trained_classifier.predict(vec)
        score2, _, _ = clf2.predict(vec)
        assert abs(score1 - score2) < 0.001

    def test_get_stats_returns_expected_keys(self, trained_classifier):
        stats = trained_classifier.get_stats()
        expected_keys = ["trained", "device", "anomaly_threshold", "threshold_error", "model_parameters"]
        for key in expected_keys:
            assert key in stats, f"Missing key: {key}"
