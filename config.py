"""
config.py
=========
Global configuration constants, thresholds, and system parameters
for the Next-Generation Adaptive Firewall.

All tunable parameters are centralized here for easy deployment configuration.
"""

import os

# =============================================================================
# NETWORK INTERFACE
# =============================================================================
NETWORK_INTERFACE = os.environ.get("FW_INTERFACE", "eth0")
PROMISCUOUS_MODE = True

# =============================================================================
# ANOMALY DETECTION THRESHOLDS
# =============================================================================
ANOMALY_SCORE_THRESHOLD = 0.85       # Score above this triggers mitigation
RATE_LIMIT_THRESHOLD = 0.65          # Score between 0.65-0.85 triggers rate limiting
FALSE_POSITIVE_TOLERANCE = 0.03      # Max acceptable FPR (3%)

# =============================================================================
# THREAT CLASSIFICATION LABELS
# =============================================================================
THREAT_LABELS = {
    0: "NORMAL",
    1: "SYN_FLOOD",
    2: "PORT_SCAN",
    3: "UDP_BURST",
    4: "ZERO_DAY_ANOMALY",
}
NUM_THREAT_CLASSES = len(THREAT_LABELS)

# =============================================================================
# FLOW AGGREGATION
# =============================================================================
FLOW_WINDOW_SHORT = 1.0              # 1-second sliding window
FLOW_WINDOW_LONG = 5.0               # 5-second sliding window
FLOW_IDLE_TIMEOUT = 60.0             # Seconds before idle flow expires
MAX_CONCURRENT_FLOWS = 50000         # Maximum tracked flows
FEATURE_QUEUE_MAXSIZE = 10000        # ML inference queue depth

# =============================================================================
# FEATURE VECTOR SPECIFICATION (15 dimensions)
# =============================================================================
FEATURE_DIM = 15
FEATURE_NAMES = [
    "src_ip_int", "dst_ip_int", "src_port", "dst_port", "protocol",
    "pkt_count", "byte_count", "avg_pkt_len", "std_pkt_len",
    "min_iat", "max_iat", "avg_iat", "flow_duration",
    "syn_flag_ratio", "rst_flag_ratio",
]

# =============================================================================
# ML MODEL CONFIGURATION
# =============================================================================
MODEL_PATH = os.environ.get("FW_MODEL_PATH", "models/classifier_model.pt")
SCALER_PATH = os.environ.get("FW_SCALER_PATH", "models/scaler.pkl")
LATENT_DIM = 64
LSTM_HIDDEN = 128
LSTM_LAYERS = 2
BATCH_SIZE = 64
LEARNING_RATE = 1e-3
TRAINING_EPOCHS = 50
INFERENCE_DEVICE = "cpu"             # "cuda" if GPU available

# =============================================================================
# REINFORCEMENT LEARNING (PPO)
# =============================================================================
RL_MODEL_PATH = os.environ.get("FW_RL_MODEL", "models/ppo_firewall.zip")
RL_TOTAL_TIMESTEPS = 500_000
RL_LEARNING_RATE = 3e-4
RL_N_STEPS = 2048
RL_BATCH_SIZE = 64
RL_N_EPOCHS = 10
RL_GAMMA = 0.99
RL_GAE_LAMBDA = 0.95
RL_CLIP_RANGE = 0.2

# RL Reward Shaping
REWARD_TRUE_POSITIVE = 10.0          # Blocked confirmed threat
REWARD_FAST_RESPONSE = 5.0           # Responded within 50ms
PENALTY_FALSE_POSITIVE = -20.0       # Blocked safe traffic
PENALTY_RULE_BLOAT = -5.0            # Too many active rules
REWARD_RULE_CLEANUP = 2.0            # Cleared stale rule

# RL Action Space
ACTION_ALLOW = 0
ACTION_DROP = 1
ACTION_RATE_LIMIT = 2
ACTION_REMOVE_RULE = 3
NUM_ACTIONS = 4

# =============================================================================
# KERNEL ENFORCEMENT (NFTABLES)
# =============================================================================
NFT_TABLE_NAME = "firewall_ai"
NFT_CHAIN_INPUT = "input"
NFT_CHAIN_RATE = "rate_limits"
NFT_SET_BLACKHOLE = "blackhole"
RULE_TTL_DEFAULT = 300               # Seconds before rule auto-expires
RULE_TTL_MAX = 3600                  # Max 1 hour
RULE_CLEANUP_INTERVAL = 30           # Background cleanup scan interval
MAX_KERNEL_RULES = 10000
RATE_LIMIT_PPS = 100                 # Packets/second for rate limiting
MITIGATION_LATENCY_TARGET_MS = 50    # Target: sub-50ms

# =============================================================================
# DATABASE & LOGGING
# =============================================================================
DATABASE_PATH = os.environ.get("FW_DB_PATH", "data/firewall_events.db")
LOG_FILE = os.environ.get("FW_LOG_FILE", "logs/firewall.log")
LOG_LEVEL = os.environ.get("FW_LOG_LEVEL", "INFO")
LOG_MAX_BYTES = 10 * 1024 * 1024     # 10 MB rotation
LOG_BACKUP_COUNT = 5

# =============================================================================
# DASHBOARD
# =============================================================================
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8050
DASHBOARD_DEBUG = False
DASHBOARD_REFRESH_INTERVAL_MS = 2000 # Live refresh rate

# =============================================================================
# SYSTEM SAFETY
# =============================================================================
WHITELIST_IPS = [
    "127.0.0.1",
    "::1",
]  # Never block these IPs

SIMULATION_MODE = os.environ.get("FW_SIMULATION", "false").lower() == "true"
