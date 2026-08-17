"""
classifier.py
=============
Hybrid LSTM-Autoencoder anomaly detection classifier for network traffic.

Architecture:
  - Encoder: LSTM(15 -> 128, 2 layers) -> FC(128 -> 64) -> Latent(64)
  - Decoder: FC(64 -> 128) -> LSTM(128 -> 128, 2 layers) -> FC(128 -> 15)
  - Classification Head: FC(64 -> 32 -> NUM_CLASSES), Softmax
  - Anomaly Score: Reconstruction error normalized to [0, 1]

Training:
  - Unsupervised autoencoder training on normal traffic baselines.
  - Optional supervised fine-tuning with labeled attack data.
  - StandardScaler preprocessing with persistence.

Inference Pipeline:
  1. Receive raw 15-dim feature vector from sniffer queue.
  2. Apply pre-fitted StandardScaler.
  3. Forward pass through LSTM encoder -> reconstruction -> MSE.
  4. Normalize MSE to [0, 1] anomaly score.
  5. Classify threat type via classification head.
  6. Return (anomaly_score, threat_label, latent_vector).
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

import config

logger = logging.getLogger("firewall.classifier")


# =============================================================================
# Neural Network Architecture
# =============================================================================

class LSTMAutoencoder(nn.Module):
    """
    Hybrid LSTM-Autoencoder for sequential traffic anomaly detection.

    The LSTM layers capture temporal patterns in network traffic flows.
    The autoencoder learns to reconstruct normal traffic; high reconstruction
    error indicates anomalous behavior.
    A classification head provides threat-type labels.
    """

    def __init__(
        self,
        feature_dim: int = config.FEATURE_DIM,
        latent_dim: int = config.LATENT_DIM,
        hidden_dim: int = config.LSTM_HIDDEN,
        num_layers: int = config.LSTM_LAYERS,
        num_classes: int = config.NUM_THREAT_CLASSES,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # ── Encoder ──────────────────────────────────────────────────────
        self.encoder_lstm = nn.LSTM(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0,
        )
        self.encoder_fc = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(128, latent_dim),
            nn.Tanh(),
        )

        # ── Decoder ──────────────────────────────────────────────────────
        self.decoder_fc = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(128, hidden_dim),
            nn.LeakyReLU(0.2),
        )
        self.decoder_lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0,
        )
        self.decoder_output = nn.Linear(hidden_dim, feature_dim)

        # ── Classification Head ──────────────────────────────────────────
        self.classifier = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, num_classes),
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

        Args:
            x: Input tensor of shape (batch, feature_dim)

        Returns:
            reconstructed: Reconstructed features (batch, feature_dim)
            latent:        Latent representation (batch, latent_dim)
            class_logits:  Threat classification logits (batch, num_classes)
        """
        # Reshape for LSTM: (batch, seq_len=1, feature_dim)
        x_seq = x.unsqueeze(1)

        # Encode
        lstm_out, _ = self.encoder_lstm(x_seq)
        lstm_last = lstm_out[:, -1, :]  # Take last hidden state
        latent = self.encoder_fc(lstm_last)

        # Decode
        decoded = self.decoder_fc(latent)
        decoded_seq = decoded.unsqueeze(1)  # (batch, 1, hidden_dim)
        decoded_lstm_out, _ = self.decoder_lstm(decoded_seq)
        reconstructed = self.decoder_output(decoded_lstm_out[:, -1, :])

        # Classify
        class_logits = self.classifier(latent)

        return reconstructed, latent, class_logits

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode only — returns latent vector."""
        x_seq = x.unsqueeze(1)
        lstm_out, _ = self.encoder_lstm(x_seq)
        return self.encoder_fc(lstm_out[:, -1, :])

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute per-sample MSE reconstruction error."""
        reconstructed, _, _ = self.forward(x)
        return torch.mean((x - reconstructed) ** 2, dim=1)


# =============================================================================
# Anomaly Classifier (High-Level Interface)
# =============================================================================

class AnomalyClassifier:
    """
    High-level interface wrapping the LSTM-Autoencoder with:
    - StandardScaler preprocessing
    - Anomaly threshold calibration
    - Threat classification
    - Model persistence (save/load)
    - Mock data generation for training/testing
    """

    def __init__(self):
        self.device = torch.device(
            config.INFERENCE_DEVICE
            if config.INFERENCE_DEVICE == "cpu" or torch.cuda.is_available()
            else "cpu"
        )
        logger.info("AnomalyClassifier using device: %s", self.device)

        self.model = LSTMAutoencoder().to(self.device)
        self.scaler = StandardScaler()
        self._threshold_error: float = 1.0  # 95th-pct error from training
        self._trained = False

    # ------------------------------------------------------------------
    # Mock Data Generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_mock_data(
        n_normal: int = 5000,
        n_attack: int = 1500,
        seed: int = 42,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Generate synthetic training data mimicking real traffic patterns.

        Returns:
            X_normal:  (n_normal, 15) normal traffic features
            X_attack:  (n_attack, 15) attack traffic features
            y_attack:  (n_attack,) attack labels (1-4)
            X_all:     Combined dataset
        """
        rng = np.random.default_rng(seed)

        # Normal traffic: moderate values, low SYN/RST ratios
        X_normal = np.column_stack([
            rng.uniform(1e8, 4e9, n_normal),      # src_ip_int
            rng.uniform(1e8, 4e9, n_normal),      # dst_ip_int
            rng.uniform(1024, 65535, n_normal),    # src_port
            rng.choice([80, 443, 22, 53, 8080], n_normal),  # dst_port
            rng.choice([6, 17], n_normal),         # protocol
            rng.uniform(5, 100, n_normal),         # pkt_count
            rng.uniform(500, 150000, n_normal),    # byte_count
            rng.uniform(100, 1400, n_normal),      # avg_pkt_len
            rng.uniform(50, 400, n_normal),        # std_pkt_len
            rng.uniform(0.001, 0.1, n_normal),     # min_iat
            rng.uniform(0.1, 2.0, n_normal),       # max_iat
            rng.uniform(0.01, 0.5, n_normal),      # avg_iat
            rng.uniform(1.0, 30.0, n_normal),      # flow_duration
            rng.uniform(0.0, 0.15, n_normal),      # syn_flag_ratio
            rng.uniform(0.0, 0.05, n_normal),      # rst_flag_ratio
        ]).astype(np.float32)

        # Attack traffic
        attacks_per_type = n_attack // 4
        remainder = n_attack - attacks_per_type * 4

        # SYN Flood: high pkt_count, high syn_ratio
        syn_flood = np.column_stack([
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1024, 65535, attacks_per_type),
            np.full(attacks_per_type, 80),
            np.full(attacks_per_type, 6),
            rng.uniform(500, 10000, attacks_per_type),
            rng.uniform(20000, 500000, attacks_per_type),
            rng.uniform(40, 100, attacks_per_type),
            rng.uniform(5, 30, attacks_per_type),
            rng.uniform(0.00001, 0.001, attacks_per_type),
            rng.uniform(0.001, 0.01, attacks_per_type),
            rng.uniform(0.0001, 0.005, attacks_per_type),
            rng.uniform(0.1, 5.0, attacks_per_type),
            rng.uniform(0.85, 1.0, attacks_per_type),
            rng.uniform(0.0, 0.02, attacks_per_type),
        ]).astype(np.float32)

        # Port Scan: low pkt_count per flow, high syn+rst ratio
        port_scan = np.column_stack([
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1024, 65535, attacks_per_type),
            rng.uniform(1, 1024, attacks_per_type),
            np.full(attacks_per_type, 6),
            rng.uniform(1, 5, attacks_per_type),
            rng.uniform(40, 300, attacks_per_type),
            rng.uniform(40, 80, attacks_per_type),
            rng.uniform(0, 10, attacks_per_type),
            rng.uniform(0.0001, 0.01, attacks_per_type),
            rng.uniform(0.01, 0.1, attacks_per_type),
            rng.uniform(0.001, 0.05, attacks_per_type),
            rng.uniform(0.01, 1.0, attacks_per_type),
            rng.uniform(0.8, 1.0, attacks_per_type),
            rng.uniform(0.3, 0.9, attacks_per_type),
        ]).astype(np.float32)

        # UDP Burst: very high pkt_count, UDP protocol
        udp_burst = np.column_stack([
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1e8, 4e9, attacks_per_type),
            rng.uniform(1024, 65535, attacks_per_type),
            rng.uniform(1, 65535, attacks_per_type),
            np.full(attacks_per_type, 17),
            rng.uniform(1000, 50000, attacks_per_type),
            rng.uniform(500000, 5000000, attacks_per_type),
            rng.uniform(500, 1400, attacks_per_type),
            rng.uniform(100, 500, attacks_per_type),
            rng.uniform(0.00001, 0.0005, attacks_per_type),
            rng.uniform(0.0005, 0.005, attacks_per_type),
            rng.uniform(0.00005, 0.001, attacks_per_type),
            rng.uniform(0.5, 10.0, attacks_per_type),
            np.zeros(attacks_per_type),
            np.zeros(attacks_per_type),
        ]).astype(np.float32)

        # Zero-day anomaly: unusual combinations
        n_zero = attacks_per_type + remainder
        zero_day = np.column_stack([
            rng.uniform(1e8, 4e9, n_zero),
            rng.uniform(1e8, 4e9, n_zero),
            rng.uniform(1024, 65535, n_zero),
            rng.uniform(1, 65535, n_zero),
            rng.choice([6, 17, 1], n_zero),
            rng.uniform(50, 5000, n_zero),
            rng.uniform(5000, 1000000, n_zero),
            rng.uniform(20, 1500, n_zero),
            rng.uniform(200, 800, n_zero),
            rng.uniform(0.0001, 0.05, n_zero),
            rng.uniform(0.5, 5.0, n_zero),
            rng.uniform(0.01, 1.0, n_zero),
            rng.uniform(0.1, 60.0, n_zero),
            rng.uniform(0.2, 0.8, n_zero),
            rng.uniform(0.1, 0.6, n_zero),
        ]).astype(np.float32)

        X_attack = np.vstack([syn_flood, port_scan, udp_burst, zero_day])
        y_attack = np.concatenate([
            np.full(attacks_per_type, 1),  # SYN_FLOOD
            np.full(attacks_per_type, 2),  # PORT_SCAN
            np.full(attacks_per_type, 3),  # UDP_BURST
            np.full(n_zero, 4),            # ZERO_DAY_ANOMALY
        ]).astype(np.int64)

        X_all = np.vstack([X_normal, X_attack])
        return X_normal, X_attack, y_attack, X_all

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train_autoencoder(
        self,
        normal_data: np.ndarray,
        epochs: int = None,
        lr: float = None,
        val_split: float = 0.1,
    ) -> Dict[str, List[float]]:
        """
        Train the LSTM-Autoencoder on NORMAL traffic only.

        Args:
            normal_data: Shape (N, 15) normal flow features
            epochs:      Training epochs (default from config)
            lr:          Learning rate (default from config)
            val_split:   Validation fraction

        Returns:
            Training history with 'train_loss' and 'val_loss' lists.
        """
        epochs = epochs or config.TRAINING_EPOCHS
        lr = lr or config.LEARNING_RATE

        logger.info("Training autoencoder on %d normal samples for %d epochs", len(normal_data), epochs)

        # Fit and apply scaler
        self.scaler.fit(normal_data)
        scaled = self.scaler.transform(normal_data).astype(np.float32)

        # Train/val split
        n_val = max(1, int(len(scaled) * val_split))
        val_data = scaled[:n_val]
        train_data = scaled[n_val:]

        train_loader = DataLoader(
            TensorDataset(torch.from_numpy(train_data)),
            batch_size=config.BATCH_SIZE,
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
                nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()
                epoch_loss += loss.item() * len(batch)

            scheduler.step()
            train_loss = epoch_loss / len(train_data)

            # Validation
            val_tensor = torch.from_numpy(val_data).to(self.device)
            with torch.no_grad():
                val_recon, _, _ = self.model(val_tensor)
                val_loss = criterion(val_recon, val_tensor).item()

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "Epoch [%d/%d] train_loss=%.6f val_loss=%.6f",
                    epoch + 1, epochs, train_loss, val_loss,
                )

        # Calibrate threshold: 95th percentile of reconstruction errors
        self.model.eval()
        with torch.no_grad():
            all_data = torch.from_numpy(scaled).to(self.device)
            errors = self.model.reconstruction_error(all_data).cpu().numpy()
        self._threshold_error = float(np.percentile(errors, 95))
        logger.info("Calibrated anomaly threshold (95th pct error): %.6f", self._threshold_error)

        self._trained = True
        return history

    def fine_tune_classifier(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 20,
        lr: float = 5e-4,
    ) -> None:
        """
        Fine-tune the classification head using labeled data.

        Args:
            X: Feature vectors (N, 15)
            y: Integer labels (N,) — 0=NORMAL, 1=SYN_FLOOD, etc.
        """
        logger.info("Fine-tuning classifier on %d labeled samples", len(X))
        scaled = self.scaler.transform(X).astype(np.float32)
        X_t = torch.from_numpy(scaled).to(self.device)
        y_t = torch.from_numpy(y.astype(np.int64)).to(self.device)

        # Freeze encoder/decoder, train only classifier
        for param in self.model.encoder_lstm.parameters():
            param.requires_grad = False
        for param in self.model.encoder_fc.parameters():
            param.requires_grad = False
        for param in self.model.decoder_fc.parameters():
            param.requires_grad = False
        for param in self.model.decoder_lstm.parameters():
            param.requires_grad = False
        for param in self.model.decoder_output.parameters():
            param.requires_grad = False

        optimizer = optim.Adam(self.model.classifier.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss()
        self.model.train()

        for epoch in range(epochs):
            optimizer.zero_grad(set_to_none=True)
            latent = self.model.encode(X_t)
            logits = self.model.classifier(latent)
            loss = criterion(logits, y_t)
            loss.backward()
            optimizer.step()
            if (epoch + 1) % 5 == 0:
                logger.info("Fine-tune epoch [%d/%d] loss=%.6f", epoch + 1, epochs, loss.item())

        # Unfreeze all
        for param in self.model.parameters():
            param.requires_grad = True
        self.model.eval()

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(
        self, feature_vec: np.ndarray
    ) -> Tuple[float, str, np.ndarray]:
        """
        Score a single 15-dim feature vector.

        Returns:
            anomaly_score:  Float in [0, 1]
            threat_label:   String label ("NORMAL", "SYN_FLOOD", etc.)
            latent_vec:     64-dim latent representation for RL agent
        """
        results = self.predict_batch(feature_vec.reshape(1, -1))
        return results[0]

    def predict_batch(
        self, features: np.ndarray
    ) -> List[Tuple[float, str, np.ndarray]]:
        """
        Score a batch of feature vectors.

        Args:
            features: Shape (N, 15)

        Returns:
            List of (anomaly_score, threat_label, latent_vec) tuples
        """
        if not self._trained:
            self._quick_init()

        scaled = self.scaler.transform(features).astype(np.float32)
        tensor = torch.from_numpy(scaled).to(self.device)

        start_t = time.perf_counter()
        self.model.eval()
        with torch.no_grad():
            reconstructed, latents, class_logits = self.model(tensor)
            errors = torch.mean((tensor - reconstructed) ** 2, dim=1).cpu().numpy()
            latents_np = latents.cpu().numpy()
            class_probs = torch.softmax(class_logits, dim=1).cpu().numpy()

        elapsed_ms = (time.perf_counter() - start_t) * 1000
        if len(features) == 1:
            logger.debug("Inference latency: %.3f ms", elapsed_ms)

        results = []
        for i in range(len(features)):
            # Normalize reconstruction error to [0, 1]
            raw_error = float(errors[i])
            anomaly_score = min(1.0, raw_error / max(self._threshold_error, 1e-8))

            # Get predicted class
            predicted_class = int(np.argmax(class_probs[i]))
            threat_label = config.THREAT_LABELS.get(predicted_class, "UNKNOWN")

            # If anomaly score is low, override to NORMAL
            if anomaly_score < config.RATE_LIMIT_THRESHOLD:
                threat_label = "NORMAL"

            results.append((anomaly_score, threat_label, latents_np[i]))

        return results

    def _quick_init(self) -> None:
        """Initialize scaler and model with synthetic data for demo use."""
        X_normal, _, _, _ = self.generate_mock_data(n_normal=1000, n_attack=0)
        self.scaler.fit(X_normal)
        self._threshold_error = 1.0
        self._trained = True
        self.model.eval()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Save model weights and scaler to disk."""
        Path(config.MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self.model.state_dict(),
            "threshold_error": self._threshold_error,
            "trained": self._trained,
        }, config.MODEL_PATH)
        with open(config.SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)
        logger.info("Saved model to %s", config.MODEL_PATH)

    def load(self) -> bool:
        """Load model weights and scaler. Returns True on success."""
        try:
            checkpoint = torch.load(
                config.MODEL_PATH, map_location=self.device, weights_only=False
            )
            self.model.load_state_dict(checkpoint["model_state"])
            self._threshold_error = checkpoint.get("threshold_error", 1.0)
            self._trained = checkpoint.get("trained", True)
            self.model.eval()
            with open(config.SCALER_PATH, "rb") as f:
                self.scaler = pickle.load(f)
            logger.info("Loaded model from %s", config.MODEL_PATH)
            return True
        except FileNotFoundError:
            logger.info("No saved model found — will train from scratch.")
            return False
        except Exception as e:
            logger.error("Error loading model: %s", e)
            return False


# ---------------------------------------------------------------------------
# Standalone training script
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logger_db
    logger_db.setup_logging()

    clf = AnomalyClassifier()

    # Generate mock data
    X_normal, X_attack, y_attack, X_all = clf.generate_mock_data()
    print(f"Normal samples: {len(X_normal)}, Attack samples: {len(X_attack)}")

    # Train autoencoder on normal traffic
    history = clf.train_autoencoder(X_normal, epochs=30)
    print(f"Final train loss: {history['train_loss'][-1]:.6f}")

    # Fine-tune classifier with labeled data
    y_all = np.concatenate([np.zeros(len(X_normal), dtype=np.int64), y_attack])
    clf.fine_tune_classifier(X_all, y_all, epochs=20)

    # Test inference
    score_n, label_n, _ = clf.predict(X_normal[0])
    score_a, label_a, _ = clf.predict(X_attack[0])
    print(f"Normal  -> Score: {score_n:.4f}, Label: {label_n}")
    print(f"Attack  -> Score: {score_a:.4f}, Label: {label_a}")

    clf.save()
    print("Model saved.")
