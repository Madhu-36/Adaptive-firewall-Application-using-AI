"""
app_dashboard.py
================
Real-time administrative dashboard for the Adaptive AI Firewall.

Built with Flask + server-sent events (SSE) for live updates.

Features:
  - Live metric counters: Total Packets, Threats, Active Blocks, Latency, FPR.
  - Threat table with blocked IPs, attack vector, anomaly score.
  - Manual override controls (Unblock IP, Retrain Model).
  - Traffic distribution chart (normal vs. malicious).
  - Auto-refreshing via JavaScript polling.

Runs on port 8050 by default.
"""

import json
import logging
import os
import threading
import time
from typing import Optional

from flask import Flask, jsonify, render_template_string, request

import config

logger = logging.getLogger("firewall.dashboard")

# =============================================================================
# Flask App Factory
# =============================================================================

def create_dashboard_app(
    db_manager=None,
    kernel_enforcer=None,
    classifier=None,
    sniffer=None,
) -> Flask:
    """
    Create and configure the Flask dashboard application.

    Args:
        db_manager:      DatabaseManager instance for querying events
        kernel_enforcer:  KernelEnforcer instance for rule management
        classifier:       AnomalyClassifier instance for retraining
        sniffer:          PacketSniffer instance for packet stats
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(24).hex()

    # Store references to system components
    app.fw_db = db_manager
    app.fw_kernel = kernel_enforcer
    app.fw_classifier = classifier
    app.fw_sniffer = sniffer

    # -----------------------------------------------------------------
    # Dashboard HTML Template (embedded for single-file simplicity)
    # -----------------------------------------------------------------

    DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Firewall Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', sans-serif;
            background: #0a0e1a;
            color: #e2e8f0;
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
            padding: 20px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1e3a5f;
        }

        .header h1 {
            font-size: 22px;
            font-weight: 600;
            letter-spacing: -0.02em;
        }

        .header h1 span { color: #60a5fa; }

        .status-dot {
            width: 10px; height: 10px;
            border-radius: 50%;
            background: #10b981;
            display: inline-block;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .metric-card {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 12px;
            padding: 20px;
            transition: border-color 0.3s;
        }

        .metric-card:hover { border-color: #3b82f6; }

        .metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #64748b;
            margin-bottom: 8px;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }

        .metric-value.danger { color: #ef4444; }
        .metric-value.warning { color: #f59e0b; }
        .metric-value.success { color: #10b981; }
        .metric-value.info { color: #3b82f6; }

        .panels {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }

        @media (max-width: 900px) {
            .panels { grid-template-columns: 1fr; }
        }

        .panel {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 12px;
            padding: 20px;
        }

        .panel h2 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #94a3b8;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748b;
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #1e3a5f;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #0f1729;
            font-size: 14px;
        }

        .badge {
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-drop { background: rgba(239,68,68,0.15); color: #ef4444; }
        .badge-rate { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .badge-normal { background: rgba(16,185,129,0.15); color: #10b981; }

        .btn {
            padding: 6px 14px;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-danger { background: #7f1d1d; color: #fca5a5; }
        .btn-danger:hover { background: #991b1b; }
        .btn-primary { background: #1e3a5f; color: #93c5fd; }
        .btn-primary:hover { background: #1e40af; }

        .dist-bar {
            display: flex;
            height: 28px;
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 8px;
        }

        .dist-normal { background: #10b981; }
        .dist-attack { background: #ef4444; }

        .dist-label {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            color: #94a3b8;
        }

        .controls {
            display: flex;
            gap: 10px;
            margin-top: 16px;
        }

        .footer {
            text-align: center;
            padding: 16px;
            color: #475569;
            font-size: 12px;
        }
    </style>
</head>
<body>

<div class="header">
    <h1><span>AI</span> Adaptive Firewall Dashboard</h1>
    <div><span class="status-dot"></span> System Active</div>
</div>

<div class="container">
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Total Events</div>
            <div class="metric-value info" id="m-total">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Threats Detected</div>
            <div class="metric-value danger" id="m-threats">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Active Kernel Blocks</div>
            <div class="metric-value warning" id="m-blocks">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Avg Response Latency</div>
            <div class="metric-value success" id="m-latency">0 ms</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">False Positive Rate</div>
            <div class="metric-value" id="m-fpr" style="color:#a78bfa">0%</div>
        </div>
    </div>

    <div class="panels">
        <div class="panel">
            <h2>Active Mitigation Rules</h2>
            <table>
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Action</th>
                        <th>Threat Type</th>
                        <th>Anomaly Score</th>
                        <th>Age (s)</th>
                        <th>Override</th>
                    </tr>
                </thead>
                <tbody id="rules-body">
                    <tr><td colspan="6" style="text-align:center;color:#475569">No active rules</td></tr>
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h2>Traffic Distribution</h2>
            <div class="dist-bar">
                <div class="dist-normal" id="bar-normal" style="width:100%"></div>
                <div class="dist-attack" id="bar-attack" style="width:0%"></div>
            </div>
            <div class="dist-label">
                <span>Normal: <b id="lbl-normal">0</b></span>
                <span>Threats: <b id="lbl-threats">0</b></span>
            </div>

            <div class="controls" style="margin-top:24px">
                <button class="btn btn-primary" onclick="retrain()">Retrain Model</button>
                <button class="btn btn-danger" onclick="flushRules()">Flush All Rules</button>
            </div>
        </div>
    </div>

    <div class="panel">
        <h2>Recent Events Log</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Threat</th>
                    <th>Score</th>
                    <th>Action</th>
                    <th>Latency</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody id="events-body">
                <tr><td colspan="7" style="text-align:center;color:#475569">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="footer">
    Next-Generation Adaptive Firewall &mdash; Real-Time Anomaly Detection &amp; Kernel-Level Rule Automation
</div>

<script>
const REFRESH_MS = {{ refresh_ms }};

async function fetchData() {
    try {
        const [statsRes, rulesRes, eventsRes, distRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/rules'),
            fetch('/api/events?limit=50'),
            fetch('/api/distribution'),
        ]);
        const stats = await statsRes.json();
        const rules = await rulesRes.json();
        const events = await eventsRes.json();
        const dist = await distRes.json();

        updateMetrics(stats);
        updateRules(rules);
        updateEvents(events);
        updateDistribution(dist);
    } catch (e) {
        console.error('Fetch error:', e);
    }
}

function updateMetrics(s) {
    document.getElementById('m-total').textContent = s.total_events.toLocaleString();
    document.getElementById('m-threats').textContent = s.total_threats.toLocaleString();
    document.getElementById('m-blocks').textContent = s.active_blocks;
    document.getElementById('m-latency').textContent = s.avg_latency_ms.toFixed(1) + ' ms';
    document.getElementById('m-fpr').textContent = s.false_positive_rate.toFixed(1) + '%';
}

function updateRules(rules) {
    const tbody = document.getElementById('rules-body');
    if (!rules.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#475569">No active rules. System operating normally.</td></tr>';
        return;
    }
    tbody.innerHTML = rules.map(r => {
        const badge = r.action === 'DROP_IP' ? 'badge-drop' : 'badge-rate';
        const scoreColor = r.anomaly_score > 0.85 ? '#ef4444' : r.anomaly_score > 0.65 ? '#f59e0b' : '#10b981';
        return `<tr>
            <td style="font-family:monospace">${r.src_ip}</td>
            <td><span class="badge ${badge}">${r.action}</span></td>
            <td>${r.threat_type}</td>
            <td style="color:${scoreColor}">${r.anomaly_score.toFixed(3)}</td>
            <td>${r.age_seconds.toFixed(0)}s</td>
            <td><button class="btn btn-danger" onclick="unblock('${r.src_ip}')">Unblock</button></td>
        </tr>`;
    }).join('');
}

function updateEvents(events) {
    const tbody = document.getElementById('events-body');
    if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#475569">No events recorded yet.</td></tr>';
        return;
    }
    tbody.innerHTML = events.slice(0, 30).map(e => {
        const badge = e.action_taken === 'DROP_IP' ? 'badge-drop' : e.action_taken === 'RATE_LIMIT_IP' ? 'badge-rate' : 'badge-normal';
        return `<tr>
            <td style="font-size:12px;color:#94a3b8">${new Date(e.timestamp).toLocaleTimeString()}</td>
            <td style="font-family:monospace">${e.source_ip}</td>
            <td>${e.threat_type}</td>
            <td>${e.anomaly_score.toFixed(3)}</td>
            <td><span class="badge ${badge}">${e.action_taken}</span></td>
            <td>${e.mitigation_latency_ms ? e.mitigation_latency_ms.toFixed(1) + 'ms' : '-'}</td>
            <td>${e.rule_status}</td>
        </tr>`;
    }).join('');
}

function updateDistribution(dist) {
    const normal = dist['NORMAL'] || 0;
    const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
    const threats = total - normal;
    const normalPct = (normal / total * 100).toFixed(1);
    const threatPct = (threats / total * 100).toFixed(1);

    document.getElementById('bar-normal').style.width = normalPct + '%';
    document.getElementById('bar-attack').style.width = threatPct + '%';
    document.getElementById('lbl-normal').textContent = normal.toLocaleString();
    document.getElementById('lbl-threats').textContent = threats.toLocaleString();
}

async function unblock(ip) {
    if (!confirm(`Unblock IP ${ip}?`)) return;
    await fetch('/api/unblock', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip}) });
    fetchData();
}

async function retrain() {
    if (!confirm('Retrain the ML model? This may take a moment.')) return;
    document.querySelector('.btn-primary').textContent = 'Retraining...';
    await fetch('/api/retrain', { method: 'POST' });
    document.querySelector('.btn-primary').textContent = 'Retrain Model';
    alert('Retrain request sent.');
}

async function flushRules() {
    if (!confirm('DANGER: Flush ALL active kernel rules?')) return;
    await fetch('/api/flush', { method: 'POST' });
    fetchData();
}

// Auto-refresh
setInterval(fetchData, REFRESH_MS);
fetchData();
</script>
</body>
</html>
"""

    # -----------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------

    @app.route("/")
    def index():
        return render_template_string(
            DASHBOARD_HTML,
            refresh_ms=config.DASHBOARD_REFRESH_INTERVAL_MS,
        )

    @app.route("/api/stats")
    def api_stats():
        if app.fw_db:
            return jsonify(app.fw_db.get_stats())
        return jsonify({
            "total_events": 0, "total_threats": 0,
            "active_blocks": 0, "avg_latency_ms": 0,
            "false_positive_rate": 0,
        })

    @app.route("/api/rules")
    def api_rules():
        if app.fw_kernel:
            return jsonify(app.fw_kernel.list_rules())
        return jsonify([])

    @app.route("/api/events")
    def api_events():
        limit = request.args.get("limit", 50, type=int)
        if app.fw_db:
            return jsonify(app.fw_db.get_recent_events(limit))
        return jsonify([])

    @app.route("/api/distribution")
    def api_distribution():
        if app.fw_db:
            return jsonify(app.fw_db.get_threat_distribution())
        return jsonify({"NORMAL": 0})

    @app.route("/api/unblock", methods=["POST"])
    def api_unblock():
        data = request.get_json()
        ip = data.get("ip", "")
        if app.fw_kernel and ip:
            import asyncio
            loop = asyncio.new_event_loop()
            loop.run_until_complete(app.fw_kernel.remove_rule(ip))
            loop.close()
            if app.fw_db:
                app.fw_db.update_rule_status(ip, "MANUALLY_REMOVED")
            logger.info("Manual unblock: %s", ip)
            return jsonify({"status": "ok", "ip": ip})
        return jsonify({"status": "error"}), 400

    @app.route("/api/retrain", methods=["POST"])
    def api_retrain():
        if app.fw_classifier:
            def _retrain():
                try:
                    X_normal, _, _, _ = app.fw_classifier.generate_mock_data()
                    app.fw_classifier.train_autoencoder(X_normal, epochs=10)
                    app.fw_classifier.save()
                    logger.info("Model retrained via dashboard")
                except Exception as e:
                    logger.error("Retrain failed: %s", e)
            threading.Thread(target=_retrain, daemon=True).start()
            return jsonify({"status": "retraining_started"})
        return jsonify({"status": "no_classifier"}), 400

    @app.route("/api/flush", methods=["POST"])
    def api_flush():
        if app.fw_kernel:
            app.fw_kernel.flush_all()
            logger.warning("All rules flushed via dashboard")
            return jsonify({"status": "flushed"})
        return jsonify({"status": "error"}), 400

    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "healthy",
            "uptime": time.time(),
            "simulation_mode": config.SIMULATION_MODE,
        })

    return app


# ---------------------------------------------------------------------------
# Standalone run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logger_db
    logger_db.setup_logging()

    app = create_dashboard_app()
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=True,
    )
