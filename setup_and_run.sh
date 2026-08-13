#!/usr/bin/env bash
# =============================================================================
# setup_and_run.sh
# =============================================================================
# Full bootstrap script for Ubuntu 22.04 LTS.
# Installs system dependencies, Python packages, configures nftables,
# and starts the Adaptive Firewall AI system.
#
# Usage:
#   chmod +x setup_and_run.sh
#   sudo ./setup_and_run.sh [--interface eth0] [--train] [--service]
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

INTERFACE="eth0"
TRAIN_ON_SETUP=false
INSTALL_SERVICE=false
PYTHON="python3"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Argument parsing ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --interface) INTERFACE="$2"; shift 2 ;;
        --train)     TRAIN_ON_SETUP=true; shift ;;
        --service)   INSTALL_SERVICE=true; shift ;;
        --python)    PYTHON="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Helper functions ─────────────────────────────────────────────────────────────
step() { echo -e "\n${CYAN}${BOLD}==> $*${RESET}"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Banner ───────────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  ┌──────────────────────────────────────────────────────────┐
  │   ADAPTIVE FIREWALL AI — Setup & Run                  │
  │   Next-Gen Anomaly Detection + Kernel-Level Automation  │
  └──────────────────────────────────────────────────────────┘
EOF
echo -e "${RESET}"
echo "  Project dir : ${PROJECT_DIR}"
echo "  Interface   : ${INTERFACE}"
echo "  Python      : ${PYTHON}"
echo ""

# ── Step 0: Root check ──────────────────────────────────────────────────────────
step "Checking root privileges"
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo ./setup_and_run.sh)"
fi
ok "Running as root"

# ── Step 1: Check OS ────────────────────────────────────────────────────────────
step "Checking OS compatibility"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" < "22.04" ]]; then
        warn "This script targets Ubuntu 22.04. Current: ${PRETTY_NAME}. Proceeding anyway..."
    else
        ok "Ubuntu ${VERSION_ID} detected"
    fi
else
    warn "Cannot detect OS. Proceeding anyway."
fi

# ── Step 2: System dependencies ───────────────────────────────────────────────────
step "Installing system dependencies"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    nftables \
    libpcap-dev \
    libnetfilter-queue-dev \
    build-essential \
    clang \
    llvm \
    linux-headers-$(uname -r) \
    libbpf-dev \
    curl \
    git \
    jq
ok "System dependencies installed"

# ── Step 3: Python virtual environment ─────────────────────────────────────────────
step "Creating Python virtual environment"
VENV_DIR="${PROJECT_DIR}/venv"
if [[ ! -d "$VENV_DIR" ]]; then
    $PYTHON -m venv "$VENV_DIR"
    ok "Virtual environment created at ${VENV_DIR}"
else
    ok "Virtual environment already exists"
fi

# Activate venv
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

# Upgrade pip
pip install --quiet --upgrade pip setuptools wheel

# ── Step 4: Python dependencies ───────────────────────────────────────────────────
step "Installing Python dependencies"
pip install --quiet -r "${PROJECT_DIR}/requirements.txt"
ok "Python dependencies installed"

# ── Step 5: Directory structure ───────────────────────────────────────────────────
step "Creating required directories"
mkdir -p "${PROJECT_DIR}/models"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/models/checkpoints"
mkdir -p "${PROJECT_DIR}/logs/ppo_tensorboard"
ok "Directories created"

# ── Step 6: Configure network interface ────────────────────────────────────────────
step "Configuring network interface: ${INTERFACE}"
if ip link show "$INTERFACE" &>/dev/null; then
    ip link set "$INTERFACE" promisc on
    ok "Interface ${INTERFACE} set to promiscuous mode"
else
    warn "Interface ${INTERFACE} not found. Update config/settings.yaml with your interface."
    # List available interfaces for guidance
    echo "  Available interfaces:"
    ip -br link show | awk '{print "    " $1}'
fi

# Update settings.yaml with the correct interface
sed -i "s/interface: .*/interface: \"${INTERFACE}\"/g" "${PROJECT_DIR}/config/settings.yaml" 2>/dev/null || true

# ── Step 7: Configure nftables ────────────────────────────────────────────────────
step "Configuring nftables"
if command -v nft &>/dev/null; then
    systemctl enable nftables 2>/dev/null || true
    systemctl start nftables 2>/dev/null || true

    # Create initial table structure (idempotent)
    nft -f - << 'NFTEOF' 2>/dev/null || true
add table inet firewall_ai
add chain inet firewall_ai input { type filter hook input priority 0; policy accept; }
add chain inet firewall_ai rate_limits { type filter hook input priority -10; policy accept; }
NFTEOF
    ok "nftables configured (table: inet firewall_ai)"
    nft list table inet firewall_ai 2>/dev/null || true
else
    warn "nftables not available. Installing..."
    apt-get install -y nftables
fi

# ── Step 8: Enable nftables in settings.yaml ────────────────────────────────────
step "Enabling nftables in configuration"
sed -i 's/enabled: false/enabled: true/g' "${PROJECT_DIR}/config/settings.yaml" 2>/dev/null || true
sed -i 's/simulation_mode: true/simulation_mode: false/g' "${PROJECT_DIR}/config/settings.yaml" 2>/dev/null || true
ok "Configuration updated"

# ── Step 9: Optional ML training ────────────────────────────────────────────────────
if [[ "$TRAIN_ON_SETUP" == true ]]; then
    step "Training ML models (this may take 10-20 minutes)"
    cd "$PROJECT_DIR"
    $PYTHON -c "
import yaml, numpy as np, sys, os
sys.path.insert(0, '.')
from models.behavior_classifier import BehaviorClassifier
from rl.firewall_env import FirewallEnv
from rl.ppo_agent import PPOFirewallAgent

with open('config/settings.yaml') as f:
    config = yaml.safe_load(f)

print('Training anomaly detector...')
clf = BehaviorClassifier(config)
rng = np.random.default_rng(42)
normal_data = rng.standard_normal((10000, 14)).astype('float32')
clf.train_unsupervised(normal_data, epochs=50)
clf.save()
print('Anomaly detector saved.')

print('Training PPO agent...')
env = FirewallEnv(config, mode='train')
agent = PPOFirewallAgent(config, env=env)
agent.initialize()
agent.train(total_timesteps=200000)
print('PPO agent saved.')
print('Training complete!')
"
    ok "Models trained and saved"
fi

# ── Step 10: Optional systemd service installation ───────────────────────────────
if [[ "$INSTALL_SERVICE" == true ]]; then
    step "Installing systemd service"
    cat > /etc/systemd/system/firewall-ai.service << EOF
[Unit]
Description=Adaptive Firewall AI Service
After=network.target nftables.service
Requires=nftables.service

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${VENV_DIR}/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=firewall-ai
Environment=PYTHONPATH=${PROJECT_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable firewall-ai
    systemctl start firewall-ai
    ok "systemd service installed and started"
    echo ""
    echo -e "  ${BOLD}Service commands:${RESET}"
    echo "    systemctl status firewall-ai"
    echo "    journalctl -u firewall-ai -f"
fi

# ── Step 11: Run tests ─────────────────────────────────────────────────────────────
step "Running test suite"
cd "$PROJECT_DIR"
python -m pytest tests/ -v --tb=short -q 2>&1 | tail -30 || warn "Some tests may have failed (non-fatal)"
ok "Tests complete"

# ── Step 12: Launch the application ──────────────────────────────────────────────────
if [[ "$INSTALL_SERVICE" != true ]]; then
    step "Starting Adaptive Firewall AI"
    echo -e "${GREEN}${BOLD}"
    echo "  Dashboard: http://localhost:8000"
    echo "  API docs:  http://localhost:8000/api/docs"
    echo "  WebSocket: ws://localhost:8000/ws/events"
    echo -e "${RESET}"
    echo "  Press Ctrl+C to stop."
    echo ""

    cd "$PROJECT_DIR"
    PYTHONPATH="$PROJECT_DIR" python -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --workers 1 \
        --log-level info
fi
