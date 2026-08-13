#!/usr/bin/env bash
# =============================================================================
# scripts/attack_simulator.sh
# =============================================================================
# Kali Linux attack simulator for testing the Adaptive Firewall AI.
# Simulates realistic attack patterns using Nmap and Hping3.
#
# Usage:
#   chmod +x attack_simulator.sh
#   sudo ./attack_simulator.sh --target <TARGET_IP> [OPTIONS]
#
# Prerequisites (Kali Linux):
#   sudo apt-get install -y nmap hping3 curl
#
# WARNING: Use ONLY against your own infrastructure or in authorized lab
# environments. Unauthorized use is illegal.
# =============================================================================

set -euo pipefail

# ───────────────────────────────────────────────────────────────────────────────
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"

TARGET_IP="192.168.1.1"
ATTACK_DURATION=30       # Seconds per attack
INTERFACE="eth0"
FIREWALL_API="http://localhost:8000"
LOGFILE="/tmp/attack_simulator_$(date +%Y%m%d_%H%M%S).log"

# ── Argument parsing ─────────────────────────────────────────────────────────────
usage() {
    echo -e "${COLOR_CYAN}Usage: $0 [OPTIONS]${COLOR_RESET}"
    echo -e "  --target   <IP>      Target IP address (default: 192.168.1.1)"
    echo -e "  --duration <secs>    Attack duration per test (default: 30)"
    echo -e "  --iface    <iface>   Network interface (default: eth0)"
    echo -e "  --api      <url>     Firewall API URL (default: http://localhost:8000)"
    echo -e "  --test     <name>    Run specific test: syn_flood|port_scan|udp_flood|slowloris|all"
    echo -e "  --help               Show this help"
    exit 0
}

TEST_FILTER="all"
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)   TARGET_IP="$2";   shift 2 ;;
        --duration) ATTACK_DURATION="$2"; shift 2 ;;
        --iface)    INTERFACE="$2";   shift 2 ;;
        --api)      FIREWALL_API="$2"; shift 2 ;;
        --test)     TEST_FILTER="$2"; shift 2 ;;
        --help)     usage ;;
        *)          echo "Unknown arg: $1"; usage ;;
    esac
done

# ── Helper functions ─────────────────────────────────────────────────────────────
log() {
    local msg="[$(date '+%H:%M:%S')] $*"
    echo -e "$msg" | tee -a "$LOGFILE"
}

log_attack() { log "${COLOR_RED}[ATTACK]${COLOR_RESET} $*"; }
log_info()   { log "${COLOR_CYAN}[INFO]${COLOR_RESET}   $*"; }
log_ok()     { log "${COLOR_GREEN}[OK]${COLOR_RESET}     $*"; }
log_warn()   { log "${COLOR_YELLOW}[WARN]${COLOR_RESET}   $*"; }

check_deps() {
    local missing=()
    for cmd in nmap hping3 curl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing dependencies: ${missing[*]}"
        log_warn "Install with: sudo apt-get install -y ${missing[*]}"
        return 1
    fi
    return 0
}

get_firewall_stats() {
    curl -s --max-time 3 "${FIREWALL_API}/api/stats" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    p = d.get('pipeline', {})
    print(f\"  Total flows: {p.get('total_flows_processed',0)}, Blocks: {p.get('total_blocks',0)}, Avg latency: {p.get('avg_latency_ms',0):.2f}ms\")
except: print('  (API not reachable)')
" 2>/dev/null || echo "  (API not reachable)"
}

wait_and_stats() {
    local secs=$1
    log_info "Running for ${secs}s... (Ctrl+C to skip to next test)"
    sleep "$secs" || true
    log_info "Firewall stats after attack:"
    get_firewall_stats
}

# ── Attack Functions ─────────────────────────────────────────────────────────────

test_syn_flood() {
    # ── TCP SYN Flood ───────────────────────────────────────────────────────────────
    # Sends high-rate TCP SYN packets to port 80 with spoofed random source IPs.
    # Characteristics: high pkt_count, syn_ratio~1.0, very low IAT.
    # Firewall should detect and DROP within 50ms.
    log_attack "TEST 1/5: TCP SYN Flood (hping3) → ${TARGET_IP}:80"
    log_info "Sending ~10,000 SYN packets/sec with random source IPs..."

    # --syn:     SYN flag only
    # --rand-source: spoofed random source IPs (simulates botnet)
    # --flood:   send as fast as possible
    # --data 0:  empty payload (pure SYN)
    # -p 80:     destination port 80
    timeout "$ATTACK_DURATION" hping3 \
        --syn \
        --rand-source \
        --flood \
        --data 0 \
        -p 80 \
        "$TARGET_IP" 2>/dev/null &
    HPING_PID=$!
    wait_and_stats "$ATTACK_DURATION"
    kill "$HPING_PID" 2>/dev/null || true
    log_ok "SYN flood test complete."
    echo ""
}

test_port_scan() {
    # ── Stealth Port Scan (Nmap SYN scan) ───────────────────────────────────
    # Nmap -sS: Half-open SYN scan (doesn't complete TCP handshake).
    # Characteristics: sequential dst_ports, consistent src_ip, low byte_count.
    # Firewall should detect port scan pattern and RATE_LIMIT or DROP.
    log_attack "TEST 2/5: Stealth Nmap SYN Port Scan → ${TARGET_IP}"
    log_info "Scanning all 65535 ports with maximum speed..."

    # -sS:   SYN scan (stealth)
    # -T5:   Insane speed (fastest Nmap timing)
    # -p-:   All ports
    # -n:    No DNS resolution
    # --open: Only show open ports
    # -oN:   Save results
    timeout "$ATTACK_DURATION" nmap \
        -sS \
        -T5 \
        -p- \
        -n \
        --open \
        -oN "/tmp/nmap_scan_$(date +%s).txt" \
        "$TARGET_IP" 2>/dev/null &
    NMAP_PID=$!
    wait_and_stats "$ATTACK_DURATION"
    kill "$NMAP_PID" 2>/dev/null || true
    log_ok "Port scan test complete."
    echo ""
}

test_udp_flood() {
    # ── UDP Flood ───────────────────────────────────────────────────────────────
    # UDP flood with random destination ports and large payload.
    # Characteristics: protocol=17, high byte_count, random dst_ports.
    log_attack "TEST 3/5: UDP Amplification Flood (hping3) → ${TARGET_IP}"
    log_info "Sending large UDP packets at high rate..."

    # --udp:   UDP mode
    # --rand-dest: random destination ports
    # --flood: maximum rate
    # --data 1400: 1400-byte payload (amplification simulation)
    timeout "$ATTACK_DURATION" hping3 \
        --udp \
        --rand-dest \
        --flood \
        --data 1400 \
        "$TARGET_IP" 2>/dev/null &
    HPING_PID=$!
    wait_and_stats "$ATTACK_DURATION"
    kill "$HPING_PID" 2>/dev/null || true
    log_ok "UDP flood test complete."
    echo ""
}

test_icmp_flood() {
    # ── ICMP Ping Flood ─────────────────────────────────────────────────────────────
    # ICMP flood with large payload.
    # Characteristics: protocol=1, very high pkt_rate, consistent pkt_size.
    log_attack "TEST 4/5: ICMP Ping Flood → ${TARGET_IP}"
    log_info "Flooding with ICMP echo requests (1400 byte payload)..."

    # --icmp:  ICMP mode (ping)
    # --flood: maximum speed
    # --data 1400: large payload
    timeout "$ATTACK_DURATION" hping3 \
        --icmp \
        --flood \
        --data 1400 \
        "$TARGET_IP" 2>/dev/null &
    HPING_PID=$!
    wait_and_stats "$ATTACK_DURATION"
    kill "$HPING_PID" 2>/dev/null || true
    log_ok "ICMP flood test complete."
    echo ""
}

test_slowloris() {
    # ── Slow Connection Attack (Slowloris-style) ──────────────────────────────
    # Opens many slow HTTP connections to exhaust server connection slots.
    # Characteristics: high concurrent connections, very slow flow, low byte rate.
    log_attack "TEST 5/5: Slowloris-style Connection Exhaustion → ${TARGET_IP}:80"
    log_info "Opening 200 slow HTTP connections..."

    # Use multiple hping3 instances with slow data rate to simulate Slowloris
    # Each connection sends 1 byte every 10 seconds
    PIDS=()
    for i in $(seq 1 20); do
        timeout "$ATTACK_DURATION" hping3 \
            --syn \
            --count 5 \
            -p 80 \
            --interval 1000 \
            "$TARGET_IP" 2>/dev/null &
        PIDS+=($!)
    done

    # Also use nmap to detect open ports during slow connection flood
    timeout "$ATTACK_DURATION" nmap \
        -sV \
        --version-intensity 0 \
        -p 80,443,22,3306,8080 \
        "$TARGET_IP" 2>/dev/null &
    PIDS+=($!)

    wait_and_stats "$ATTACK_DURATION"

    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    log_ok "Slowloris-style test complete."
    echo ""
}

# ── Main Execution ───────────────────────────────────────────────────────────────────────
main() {
    echo -e "${COLOR_CYAN}"
    echo "=========================================================="
    echo "  ADAPTIVE FIREWALL AI — Attack Simulator"
    echo "  Target: ${TARGET_IP} | Duration: ${ATTACK_DURATION}s/test"
    echo "  Log: ${LOGFILE}"
    echo "=========================================================="
    echo -e "${COLOR_RESET}"

    log_info "Checking root privileges..."
    if [[ $EUID -ne 0 ]]; then
        log_warn "hping3 requires root. Re-run with sudo."
    fi

    log_info "Checking dependencies..."
    check_deps || true

    log_info "Initial firewall state:"
    get_firewall_stats
    echo ""

    # Run selected tests
    case "$TEST_FILTER" in
        syn_flood)  test_syn_flood ;;
        port_scan)  test_port_scan ;;
        udp_flood)  test_udp_flood ;;
        icmp_flood) test_icmp_flood ;;
        slowloris)  test_slowloris ;;
        all)
            test_syn_flood
            test_port_scan
            test_udp_flood
            test_icmp_flood
            test_slowloris
            ;;
        *)
            log_warn "Unknown test: ${TEST_FILTER}. Use: syn_flood|port_scan|udp_flood|icmp_flood|slowloris|all"
            exit 1
            ;;
    esac

    echo -e "${COLOR_GREEN}"
    echo "=========================================================="
    echo "  All attack simulations complete."
    echo "  Final firewall state:"
    get_firewall_stats
    echo "  Full log saved to: ${LOGFILE}"
    echo "=========================================================="
    echo -e "${COLOR_RESET}"
}

main "$@"
