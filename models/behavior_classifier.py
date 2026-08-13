"""
models/behavior_classifier.py
==============================
Deep Learning anomaly detection classifier for network traffic flows.

Architecture:
  - Encoder MLP: 14 → 128 → 256 → 128 → latent(64)
  - Decoder MLP: 64 → 128 → 256 → 128 → 14
  - Trained as an autoencoder on NORMAL traffic to learn a behavioral baseline.
  - Anomaly Score = reconstruction error normalized to [0, 1] relative to
    the 95th-percentile reconstruction error seen during training.
  - A supervised classification head (64 → 32 → 1, sigmoid) is optionally
    fine-tuned when labeled attack data is available.

Inference pipeline:
  1. Receive raw 14-dim feature vector from PacketEngine queue.
  2. Apply pre-fitted StandardScaler.
  3. Forward pass through encoder → reconstruction → compute MSE loss.
  4. Normalize loss to [0, 1] anomaly score.
  5. Return (anomaly_score, is_anomaly, latent_vector).

Model Performance Targets:
  - Inference latency: < 2ms per vector (CPU), < 0.5ms (GPU)
  - Detection accuracy: > 96%, False positive rate: < 3%
"""

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger(__name__)

FEATURE_DIM = 14  # Must match PacketEngine feature vector dimension
LATENT_DIM = 64


# =============================================================================
# Neural Network Architecture
# =============================================================================

class EncoderBlock(nn.Module):
    """A single encoder residual block with BatchNorm and LeakyReLU."""

    def __init__(self, in_dim: int, out_dim: int, dropout: float = 0.3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, out_dim),
            nn.BatchNorm1d(out_dim),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(dropout),
        )
        # Residual projection if dimensions differ
        self.residual = nn.Linear(in_dim, out_dim) if in_dim != out_dim else nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x) + self.residual(x)


class AnomalyAutoencoder(nn.Module):
    """
    Autoencoder-based anomaly detector.

    The encoder compresses traffic features into a latent representation.
    The decoder reconstructs the original features.
    High reconstruction error = the traffic pattern deviates from learned normal behavior.
    """

    def __init__(self, feature_dim: int = FEATURE_DIM, latent_dim: int = LATENT_DIM):
        super().__init__()
        self.feature_dim = feature_dim
        self.latent_dim = latent_dim

        # ── Encoder ──────────────────────────────────────────────────────────
        self.encoder = nn.Sequential(
            EncoderBlock(feature_dim, 128, dropout=0.2),
            EncoderBlock(128, 256, dropout=0.3),
            EncoderBlock(256, 128, dropout=0.2),
            nn.Linear(128, latent_dim),
            nn.Tanh(),  # Bounded latent space
        )

        # ── Decoder ──────────────────────────────────────────────────────────
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(128, 256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(256, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(128, feature_dim),
        )

        # ── Supervised Classification Head (fine-tuning) ──────────────────────
        self.classifier = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

        self._init_weights()

    def _init_weights(self):
        """Xavier initialization for stable training."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass.

        Returns:
            reconstructed: Reconstructed feature vector
            latent:        Latent representation
            class_score:   Supervised anomaly probability (0=normal, 1=attack)
        """
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        class_score = self.classifier(latent)
        return reconstructed, latent, class_score

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode only — returns latent vector."""
        return self.encoder(x)

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute per-sample MSE reconstruction error."""
        reconstructed, _, _ = self.forward(x)
        return torch.mean((x - reconstructed) ** 2, dim=1)


# =============================================================================
# Behavior Classifier (high-level interface)
# =============================================================================

class BehaviorClassifier:
    """
    High-level interface for anomaly detection.

    Wraps AnomalyAutoencoder with:
    - StandardScaler preprocessing
    - Anomaly threshold calibration
    - Batched inference for throughput
    - Model persistence (save/load)
    """

    def __init__(self, config: dict):
        ml_cfg = config.get("ml", {})
        self.model_path = ml_cfg.get("model_path", "models/behavior_classifier.pt")
        self.scaler_path = ml_cfg.get("scaler_path", "models/scaler.pkl")
        self.anomaly_threshold = ml_cfg.get("anomaly_threshold", 0.65)
        self.batch_size = ml_cfg.get("batch_size", 32)
        device_str = ml_cfg.get("inference_device", "cpu")

        self.device = torch.device(device_str if torch.cuda.is_available() or device_str == "cpu" else "cpu")
        logger.info("BehaviorClassifier using device: %s", self.device)

        self.model = AnomalyAutoencoder().to(self.device)
        self.scaler = StandardScaler()
        self._threshold_error: float = 1.0   # 95th-pct reconstruction error from training
        self._trained = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train_unsupervised(
        self,
        normal_data: np.ndarray,
        epochs: int = 50,
        lr: float = 1e-3,
        val_split: float = 0.1,
    ) -> Dict[str, List[float]]:
        """
        Train the autoencoder on NORMAL traffic data only.

        Args:
            normal_data: Shape (N, 14) — only normal (non-attack) flows
            epochs:      Training epochs
            lr:          Learning rate
            val_split:   Fraction of data held out for validation

        Returns:
            Training history dict with 'train_loss' and 'val_loss' lists.
        """
        logger.info("Training autoencoder on %d normal samples for %d epochs", len(normal_data), epochs)

        # Fit and apply scaler
        self.scaler.fit(normal_data)
        scaled = self.scaler.transform(normal_data).astype(np.float32)

        # Train/val split
        n_val = max(1, int(len(scaled) * val_split))
        val_data = scaled[:n_val]
        train_data = scaled[n_val:]

        train_tensor = torch.from_numpy(train_data)
        val_tensor = torch.from_numpy(val_data)

        train_loader = DataLoader(
            TensorDataset(train_tensor),
            batch_size=self.batch_size,
            shuffle=True,
            num_workers=0,
            pin_memory=(self.device.type == "cuda"),
        )

        optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        criterion = nn.MSELoss()

        history = {"train_loss": [], "val_loss": []}
        self.model.train()

        for epoch in range(epochs):
            epoch_loss = 0.0
            for (batch,) in train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad(set_to_none=True)
                reconstructed, _, _ = self.model(batch)
                loss = criterion(reconstructed, batch)
                loss.backward()
                # Gradient clipping for stability
                nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()
                epoch_loss += loss.item() * len(batch)

            scheduler.step()
            train_loss = epoch_loss / len(train_data)

            # Validation
            with torch.no_grad():
                val_tensor_dev = val_tensor.to(self.device)
                val_recon, _, _ = self.model(val_tensor_dev)
                val_loss = criterion(val_recon, val_tensor_dev).item()

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)

            if (epoch + 1) % 10 == 0:
                logger.info("Epoch [%d/%d] train_loss=%.6f val_loss=%.6f",
                            epoch + 1, epochs, train_loss, val_loss)

        # Calibrate threshold: 95th percentile of reconstruction errors on training data
        self.model.eval()
        with torch.no_grad():
            all_data = torch.from_numpy(scaled).to(self.device)
            errors = self.model.reconstruction_error(all_data).cpu().numpy()
        self._threshold_error = float(np.percentile(errors, 95))
        logger.info("Calibrated anomaly threshold (95th pct error): %.6f", self._threshold_error)

        self._trained = True
        return history

    def fine_tune_supervised(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 20,
        lr: float = 5e-4,
    ) -> None:
        """
        Fine-tune the classifier head using labeled data.

        Args:
            X: Feature vectors (N, 14)
            y: Binary labels (N,) — 0=normal, 1=attack
        """
        logger.info("Fine-tuning classifier head on %d labeled samples", len(X))
        scaled = self.scaler.transform(X).astype(np.float32)
        X_t = torch.from_numpy(scaled).to(self.device)
        y_t = torch.from_numpy(y.astype(np.float32)).unsqueeze(1).to(self.device)

        # Freeze encoder/decoder — only train classifier head
        for param in self.model.encoder.parameters():
            param.requires_grad = False
        for param in self.model.decoder.parameters():
            param.requires_grad = False

        optimizer = optim.Adam(self.model.classifier.parameters(), lr=lr)
        criterion = nn.BCELoss()
        self.model.train()

        for epoch in range(epochs):
            optimizer.zero_grad(set_to_none=True)
            latent = self.model.encode(X_t)
            preds = self.model.classifier(latent)
            loss = criterion(preds, y_t)
            loss.backward()
            optimizer.step()
            if (epoch + 1) % 5 == 0:
                logger.info("Fine-tune epoch [%d/%d] loss=%.6f", epoch + 1, epochs, loss.item())

        # Unfreeze all parameters
        for param in self.model.parameters():
            param.requires_grad = True
        self.model.eval()

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, feature_vec: np.ndarray) -> Tuple[float, bool, np.ndarray]:
        """
        Score a single flow's 14-dimensional feature vector.

        Args:
            feature_vec: Shape (14,) — raw (unscaled) feature vector

        Returns:
            anomaly_score:  Float in [0, 1]; higher = more anomalous
            is_anomaly:     Bool — True if score exceeds threshold
            latent_vec:     64-dim latent representation for RL state space
        """
        return self.predict_batch(feature_vec.reshape(1, -1))[0]

    def predict_batch(self, features: np.ndarray) -> List[Tuple[float, bool, np.ndarray]]:
        """
        Score a batch of feature vectors.

        Args:
            features: Shape (N, 14)

        Returns:
            List of (anomaly_score, is_anomaly, latent_vec) tuples
        """
        if not self._trained:
            logger.warning("Model not trained — initializing with random weights.")
            # Generate synthetic training data for demo purposes
            self._quick_init()

        scaled = self.scaler.transform(features).astype(np.float32)
        tensor = torch.from_numpy(scaled).to(self.device)

        start_t = time.perf_counter()
        self.model.eval()
        with torch.no_grad():
            reconstructed, latents, class_scores = self.model(tensor)
            errors = torch.mean((tensor - reconstructed) ** 2, dim=1).cpu().numpy()
            latents_np = latents.cpu().numpy()
            class_scores_np = class_scores.squeeze(1).cpu().numpy()

        elapsed_ms = (time.perf_counter() - start_t) * 1000
        if len(features) == 1:
            logger.debug("Inference latency: %.3f ms", elapsed_ms)

        results = []
        for i in range(len(features)):
            # Normalize reconstruction error to [0, 1] using calibrated threshold
            raw_error = float(errors[i])
            norm_score = min(1.0, raw_error / max(self._threshold_error, 1e-8))

            # Blend with classifier output for better accuracy when fine-tuned
            blended_score = 0.6 * norm_score + 0.4 * float(class_scores_np[i])
            is_anomaly = blended_score > self.anomaly_threshold

            results.append((blended_score, is_anomaly, latents_np[i]))

        return results

    def _quick_init(self) -> None:
        """Initialize scaler and model with synthetic data for demo/test use."""
        rng = np.random.default_rng(0)
        dummy = rng.standard_normal((1000, FEATURE_DIM)).astype(np.float32)
        self.scaler.fit(dummy)
        self._threshold_error = 1.0
        self._trained = True
        self.model.eval()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Save model weights and scaler to disk."""
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self.model.state_dict(),
            "threshold_error": self._threshold_error,
            "trained": self._trained,
        }, self.model_path)
        with open(self.scaler_path, "wb") as f:
            pickle.dump(self.scaler, f)
        logger.info("Saved model to %s and scaler to %s", self.model_path, self.scaler_path)

    def load(self) -> bool:
        """Load model weights and scaler from disk. Returns True on success."""
        try:
            checkpoint = torch.load(self.model_path, map_location=self.device, weights_only=True)
            self.model.load_state_dict(checkpoint["model_state"])
            self._threshold_error = checkpoint.get("threshold_error", 1.0)
            self._trained = checkpoint.get("trained", True)
            self.model.eval()

            with open(self.scaler_path, "rb") as f:
                self.scaler = pickle.load(f)

            logger.info("Loaded model from %s", self.model_path)
            return True
        except FileNotFoundError:
            logger.info("No saved model found at %s — will train from scratch.", self.model_path)
            return False
        except Exception as e:
            logger.error("Error loading model: %s", e)
            return False

    def get_stats(self) -> dict:
        """Return current model statistics."""
        return {
            "trained": self._trained,
            "device": str(self.device),
            "anomaly_threshold": self.anomaly_threshold,
            "threshold_error": self._threshold_error,
            "model_parameters": sum(p.numel() for p in self.model.parameters()),
        }


# ---------------------------------------------------------------------------
# Module entry-point for standalone testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import yaml
    logging.basicConfig(level=logging.INFO)

    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)

    clf = BehaviorClassifier(cfg)

    # Generate synthetic training data: 5000 normal samples
    rng = np.random.default_rng(42)
    normal_data = rng.standard_normal((5000, FEATURE_DIM)).astype(np.float32)

    print("Training autoencoder...")
    history = clf.train_unsupervised(normal_data, epochs=30)
    print(f"Final train loss: {history['train_loss'][-1]:.6f}")

    # Test inference
    normal_vec = rng.standard_normal(FEATURE_DIM).astype(np.float32)
    attack_vec = rng.standard_normal(FEATURE_DIM).astype(np.float32) * 10  # Large outlier

    score_n, is_anom_n, _ = clf.predict(normal_vec)
    score_a, is_anom_a, _ = clf.predict(attack_vec)

    print(f"Normal  — Score: {score_n:.4f}, Is Anomaly: {is_anom_n}")
    print(f"Attack  — Score: {score_a:.4f}, Is Anomaly: {is_anom_a}")

    clf.save()
    print("Model saved.")
