# A Next-Generation Adaptive Firewall: Real-Time Anomaly Detection and Kernel-Level Rule Automation

This project implements an autonomous, AI-driven network firewall capable of real-time anomaly detection and kernel-level mitigation.

## System Architecture

The firewall operates through a multi-stage pipeline:

1. **Packet Engine (Scapy)**: Captures network traffic in promiscuous mode and tracks 5-tuple flow state.
2. **Behavior Classifier (Autoencoder)**: An ML model that scores flows for anomalous behavior based on 14 extracted features (e.g., packet sizes, inter-arrival times, TCP flags).
3. **PPO Agent (Stable-Baselines3)**: A Deep Reinforcement Learning agent that takes the anomaly score and latent representation to decide on the best mitigation strategy (ALLOW, RATE_LIMIT, DROP).
4. **Kernel Manager (nftables & eBPF)**: Applies the chosen action directly at the Linux kernel level with ultra-low latency (< 50ms total response time). Rules are auto-expired based on TTL.

## Project Structure

- `app/`: FastAPI web server and WebSocket dashboard.
- `config/`: System configuration (`settings.yaml`).
- `kernel/`: Interface to Linux `nftables` and high-performance `eBPF/XDP`.
- `models/`: PyTorch Autoencoder definition and ML pipeline.
- `rl/`: OpenAI Gym environment and PPO reinforcement learning agent.
- `sniffer/`: Async packet capture and flow extraction.
- `tests/`: Pytest suite for all components.
- `scripts/`: Helper scripts for attack simulation.

## Setup Instructions (Ubuntu 22.04 LTS)

1. Run the setup script to install system dependencies (nftables, libpcap) and Python packages:
   ```bash
   sudo ./setup_and_run.sh
   ```

2. Alternatively, manually install requirements:
   ```bash
   sudo apt-get update
   sudo apt-get install -y libpcap-dev nftables python3-pip
   pip install -r requirements.txt
   ```

## Running the Firewall

To launch the firewall and the web dashboard:

```bash
sudo python3 run.py
```

*Note: Root privileges are required for packet sniffing and kernel rule modification.*

Access the live dashboard at: `http://localhost:8000/`

## Testing

Run the unit test suite:
```bash
pytest tests/ -v
```

Simulate an attack (requires `hping3` and `nmap`):
```bash
sudo ./scripts/attack_simulator.sh 127.0.0.1
```
