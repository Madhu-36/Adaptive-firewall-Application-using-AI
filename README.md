# A Next-Generation Adaptive Firewall: Real-Time Anomaly Detection and Kernel-Level Rule Automation

An autonomous, AI-driven network firewall capable of real-time anomaly detection and kernel-level mitigation.

## System Architecture

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│   Sniffer   │───>│  Classifier  │───>│  DRL Agent   │───>│ Kernel Enforcer  │
│ (Scapy)     │    │ (LSTM-AE)    │    │ (PPO)        │    │ (nftables)       │
└─────────────┘    └──────────────┘    └──────────────┘    └──────────────────┘
       │                  │                   │                      │
       └──────────────────┴───────────────────┴──────────────────────┘
                                    │
                          ┌─────────┴─────────┐
                          │   SQLite Logger    │
                          │   Flask Dashboard  │
                          └───────────────────┘
```

### Pipeline Stages

1. **Packet Sniffer** (`sniffer.py`): Captures live traffic via Scapy in promiscuous mode. Aggregates packets into 5-tuple flows and extracts 15-dimensional behavioral feature vectors.
2. **LSTM-Autoencoder Classifier** (`classifier.py`): Hybrid deep learning model trained on normal traffic baselines. Outputs an anomaly score [0, 1] and threat classification (NORMAL, SYN_FLOOD, PORT_SCAN, UDP_BURST, ZERO_DAY_ANOMALY).
3. **PPO Reinforcement Learning Agent** (`drl_agent.py`): Custom Gymnasium environment with a self-healing loop. Makes adaptive decisions: ALLOW, DROP_IP, RATE_LIMIT_IP, or REMOVE_RULE.
4. **Kernel Enforcer** (`kernel_enforcer.py`): Interfaces with Linux nftables for sub-50ms rule injection. Maintains automatic TTL-based rule expiry to prevent kernel table bloat.
5. **Database Logger** (`logger_db.py`): Thread-safe SQLite logging with WAL mode, batched writes, and structured audit trails.
6. **Flask Dashboard** (`app_dashboard.py`): Real-time web UI showing live metrics, active rules, threat distribution, and manual override controls.

## Target Performance Metrics

| Metric | Target |
|--------|--------|
| Detection Accuracy | > 96% |
| False Positive Rate | < 3% |
| Mitigation Latency | < 50ms |
| Concurrent Connections | 50,000+ |

## Project Structure

```
├── config.py            # Global configuration constants
├── sniffer.py           # Live packet capture & feature extraction
├── classifier.py        # LSTM-Autoencoder anomaly detector
├── drl_agent.py         # PPO reinforcement learning agent
├── kernel_enforcer.py   # nftables kernel rule engine
├── logger_db.py         # SQLite database & audit logging
├── app_dashboard.py     # Flask web dashboard
├── main.py              # Master orchestrator
├── requirements.txt     # Python dependencies
├── models/              # Saved ML/RL model weights
├── data/                # SQLite database
└── logs/                # Rotating log files
```

## Quick Start

### Ubuntu 22.04 LTS (Production)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv libpcap-dev nftables

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Run the firewall (requires root for packet capture & nftables)
sudo python3 main.py
```

### Windows / macOS (Simulation Mode)

```bash
# Set simulation mode
set FW_SIMULATION=true   # Windows
export FW_SIMULATION=true # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Run in simulation mode
python main.py
```

### Access the Dashboard

Open your browser to `http://localhost:8050`

## Training Models Independently

```bash
# Train the ML classifier
python classifier.py

# Train the RL agent
python drl_agent.py
```

## Module Details

### ML Classifier Architecture
- **Encoder**: LSTM(15→128, 2 layers) → FC(128→64) → Latent(64)
- **Decoder**: FC(64→128) → LSTM(128→128, 2 layers) → FC(128→15)
- **Classification Head**: FC(64→32→5), Softmax
- **Anomaly Score**: Normalized reconstruction error [0, 1]

### RL Agent (PPO)
- **State Space**: 8-dimensional (anomaly score, connection rate, packet loss, FP history, active rules, threat class, flow duration, avg latency)
- **Action Space**: Discrete(4) — ALLOW, DROP_IP, RATE_LIMIT_IP, REMOVE_RULE
- **Reward Design**: +10 true positive, +5 fast response bonus, -20 false positive, -5 rule bloat, +2 cleanup

### Kernel Enforcement (nftables)
- Uses `nft` CLI with named sets and timeout flags for automatic IP expiry
- Rule injection target: < 50ms
- Automatic TTL-based cleanup every 30 seconds
- Emergency cleanup when rule capacity (10,000) is reached
