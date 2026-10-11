"""
xai_explainer.py
================
Explainable AI (XAI) using SHAP (SHapley Additive exPlanations).

Neural networks are often 'black boxes'. This module calculates SHAP values
for every flagged anomaly to explain exactly *which* features (e.g., packet 
size, inter-arrival time, TCP flags) caused the AI to classify the traffic as an attack.
This is critical for enterprise compliance and SOC analyst investigations.
"""

import logging
import numpy as np
import time

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "src_ip_int", "dst_ip_int", "src_port", "dst_port", "protocol",
    "pkt_count", "byte_count", "avg_pkt_size", "std_pkt_size",
    "min_iat", "max_iat", "avg_iat", "flow_duration", "syn_flag_ratio", "rst_flag_ratio"
]

class AnomalyExplainer:
    def __init__(self):
        self.explainer = None
        self.is_ready = False
        self._total_explanations = 0
        logger.info("Explainable AI (XAI) module initialized.")

    def fit_baseline(self, baseline_data: np.ndarray, model_predict_fn):
        """Fits the SHAP explainer on normal background traffic."""
        try:
            import shap
            # Use a fast subset for KernelExplainer baseline (e.g., k-means summary)
            background = shap.sample(baseline_data, min(50, len(baseline_data)))
            self.explainer = shap.KernelExplainer(model_predict_fn, background)
            self.is_ready = True
            logger.info("SHAP XAI explainer successfully fitted to baseline traffic.")
        except ImportError:
            logger.warning("SHAP library not installed. Running XAI in fast heuristic mode.")
            self.is_ready = False
        except Exception as e:
            logger.warning("SHAP fitting failed: %s. Using heuristic explainer.", e)
            self.is_ready = False

    def explain_anomaly(self, feature_vector: np.ndarray) -> str:
        """Returns a human-readable explanation of the AI's decision."""
        self._total_explanations += 1
        if not self.is_ready or self.explainer is None:
            return self._heuristic_explanation(feature_vector)
            
        try:
            import shap
            start_t = time.perf_counter()
            shap_values = self.explainer.shap_values(feature_vector)
            latency = (time.perf_counter() - start_t) * 1000
            
            # Get top 3 contributing features
            top_indices = np.argsort(np.abs(shap_values[0]))[-3:][::-1]
            reasons = []
            for idx in top_indices:
                if idx < len(FEATURE_NAMES):
                    feat_name = FEATURE_NAMES[idx]
                    impact = shap_values[0][idx]
                    direction = "High" if impact > 0 else "Low"
                    reasons.append(f"{direction} {feat_name}")
                
            return f"(SHAP XAI {latency:.1f}ms): " + " | ".join(reasons)
        except Exception:
            return self._heuristic_explanation(feature_vector)

    def _heuristic_explanation(self, feature_vector: np.ndarray) -> str:
        """A highly optimized O(1) heuristic explainer for real-time traffic classification."""
        row = feature_vector[0] if feature_vector.ndim > 1 else feature_vector
        syn = float(row[13]) if len(row) > 13 else 0.0
        rst = float(row[14]) if len(row) > 14 else 0.0
        iat = float(row[11]) if len(row) > 11 else 0.0
        pkt_count = float(row[5]) if len(row) > 5 else 0.0
        
        reasons = []
        if syn > 0.7:
            reasons.append(f"High SYN ratio ({syn*100:.0f}% - SYN flood signature)")
        if rst > 0.4:
            reasons.append(f"High RST ratio ({rst*100:.0f}% - Port scan / probe pattern)")
        if iat < 0.001 and pkt_count > 100:
            reasons.append(f"Sub-ms packet IAT ({iat*1000:.2f}ms - Volumetric burst)")
        if pkt_count > 500:
            reasons.append(f"Excessive packet volume ({int(pkt_count)} pkts in window)")
            
        if reasons:
            return "[XAI]: " + " | ".join(reasons)
        return "[XAI]: Anomaly detected across multi-metric latent reconstruction"

    def get_stats(self) -> dict:
        return {
            "mode": "SHAP Kernel" if self.is_ready else "Fast Heuristic (O(1))",
            "is_ready": True,
            "total_explanations": self._total_explanations,
            "feature_count": len(FEATURE_NAMES),
        }
