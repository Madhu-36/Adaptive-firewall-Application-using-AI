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
    "min_iat", "max_iat", "avg_iat", "flow_duration", "syn_flag_ratio"
]

class AnomalyExplainer:
    def __init__(self):
        self.explainer = None
        self.is_ready = False
        logger.info("Explainable AI (XAI) module initialized.")

    def fit_baseline(self, baseline_data: np.ndarray, model_predict_fn):
        """Fits the SHAP explainer on normal background traffic."""
        try:
            import shap
            # Use a fast subset for KernelExplainer baseline (e.g., k-means summary)
            background = shap.sample(baseline_data, 100)
            self.explainer = shap.KernelExplainer(model_predict_fn, background)
            self.is_ready = True
            logger.info("SHAP XAI explainer successfully fitted to baseline traffic.")
        except ImportError:
            logger.warning("SHAP library not installed. Running XAI in heuristic mode.")
            self.is_ready = False

    def explain_anomaly(self, feature_vector: np.ndarray) -> str:
        """Returns a human-readable explanation of the AI's decision."""
        if not self.is_ready:
            # Fallback heuristic explanation if SHAP isn't installed
            return self._heuristic_explanation(feature_vector)
            
        import shap
        start_t = time.perf_counter()
        shap_values = self.explainer.shap_values(feature_vector)
        latency = (time.perf_counter() - start_t) * 1000
        
        # Get top 3 contributing features
        top_indices = np.argsort(np.abs(shap_values[0]))[-3:][::-1]
        
        explanation = f"(XAI generated in {latency:.1f}ms): "
        reasons = []
        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            impact = shap_values[0][idx]
            direction = "High" if impact > 0 else "Low"
            reasons.append(f"{direction} {feat_name}")
            
        return explanation + " Driven by -> " + " | ".join(reasons)

    def _heuristic_explanation(self, feature_vector: np.ndarray) -> str:
        """A highly optimized O(1) heuristic explainer for simulation mode."""
        # Index 13 is syn_flag_ratio, Index 5 is pkt_count, Index 11 is avg_iat
        syn = feature_vector[0][13]
        iat = feature_vector[0][11]
        
        if syn > 0.8:
            return "(XAI Heuristic): Abnormally high SYN ratio. Highly indicative of SYN Flood DDoS."
        elif iat < 0.001:
            return "(XAI Heuristic): Inter-arrival time is nearly zero. Suggests automated volumetric attack."
        else:
            return "(XAI Heuristic): Statistical deviation across multiple flow metrics."
