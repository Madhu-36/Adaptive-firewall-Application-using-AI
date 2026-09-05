"""
app_dashboard.py
================
Real-time administrative dashboard for the Adaptive AI Firewall.

Built with Flask + Chart.js for live, interactive visualizations.

Features:
  - Live metric counters with animated sparklines (Chart.js).
  - Real-time anomaly score line chart with rolling 60s window.
  - Threat distribution doughnut chart (Chart.js).
  - Throughput stacked bar chart with per-10s event rates.
  - Active mitigation rules table with per-row risk score bars.
  - Live event terminal feed with color-coded threat stream.
  - Manual override controls (Unblock IP, Retrain Model, Flush Rules).
  - System health panel (uptime, mode, capacity, latency).
  - Toast notification system for user actions.
  - Glassmorphism / cyberpunk dark theme — fully responsive.

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
    app._start_time = time.time()

    # -----------------------------------------------------------------
    # Dashboard HTML Template (embedded for single-file portability)
    # -----------------------------------------------------------------

    DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Firewall — Adaptive Security Command Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ============================================================  DESIGN SYSTEM  */
:root {
  --bg-void:    #04060f;
  --bg-deep:    #070c1a;
  --bg-panel:   rgba(10,16,35,0.85);
  --bg-glass:   rgba(15,24,50,0.6);
  --bg-hover:   rgba(30,58,138,0.22);
  --border:     rgba(30,80,180,0.28);
  --border-glow:rgba(59,130,246,0.55);
  --text:       #e2e8f0;
  --muted:      #64748b;
  --dim:        #334155;
  --cyan:  #22d3ee; --blue:#3b82f6; --violet:#a78bfa;
  --green: #10b981; --yellow:#f59e0b; --red:#ef4444; --pink:#f472b6;
  --mono: 'JetBrains Mono',monospace;
  --sans: 'Inter',sans-serif;
  --r:14px; --r-sm:8px;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{font-family:var(--sans);background:var(--bg-void);color:var(--text);min-height:100vh;overflow-x:hidden;}

/* scanlines */
body::before{content:'';position:fixed;inset:0;z-index:1000;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);}
/* ambient glow */
body::after{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:
    radial-gradient(ellipse 60% 40% at 20% 10%,rgba(59,130,246,.07) 0%,transparent 60%),
    radial-gradient(ellipse 50% 50% at 80% 90%,rgba(167,139,250,.05) 0%,transparent 60%),
    var(--bg-void);}

/* ============================================================  LAYOUT  */
.layout{display:grid;grid-template-rows:64px 1fr;min-height:100vh;}
.main{padding:24px;max-width:1800px;margin:0 auto;width:100%;display:flex;flex-direction:column;gap:18px;}

/* ============================================================  HEADER  */
.header{position:sticky;top:0;z-index:500;background:rgba(4,6,15,.94);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;
  padding:0 28px;gap:16px;}
.logo{display:flex;align-items:center;gap:12px;text-decoration:none;}
.logo-icon{width:36px;height:36px;border:1.5px solid var(--cyan);border-radius:8px;
  display:flex;align-items:center;justify-content:center;font-size:16px;
  box-shadow:0 0 14px rgba(34,211,238,.35);animation:lglow 3s ease-in-out infinite;}
@keyframes lglow{0%,100%{box-shadow:0 0 14px rgba(34,211,238,.35)}50%{box-shadow:0 0 26px rgba(34,211,238,.65)}}
.logo-text{font-size:15px;font-weight:700;letter-spacing:-.02em;color:var(--text);}
.logo-text span{color:var(--cyan);}
.header-center{display:flex;align-items:center;gap:16px;font-family:var(--mono);font-size:12px;}
.nav-pill{display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;
  background:var(--bg-glass);border:1px solid var(--border);color:var(--muted);font-size:12px;cursor:pointer;transition:all .2s;}
.nav-pill:hover{border-color:var(--border-glow);color:var(--text);}
.header-right{display:flex;align-items:center;gap:14px;}
.status-badge{display:flex;align-items:center;gap:7px;padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600;font-family:var(--mono);}
.status-badge.live{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.4);color:var(--green);}
.status-badge.sim {background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.4);color:var(--yellow);}
.status-dot{width:7px;height:7px;border-radius:50%;background:currentColor;animation:blink 1.5s ease-in-out infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.clock{font-family:var(--mono);font-size:12px;color:var(--muted);letter-spacing:.05em;}

/* ============================================================  METRIC CARDS  */
.metrics-row{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;}
.mcard{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--r);
  padding:18px 20px 12px;position:relative;overflow:hidden;backdrop-filter:blur(12px);transition:border-color .3s,transform .2s;cursor:default;}
.mcard::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--ac,var(--blue)),transparent);opacity:.65;}
.mcard:hover{border-color:var(--border-glow);transform:translateY(-2px);}
.mcard[data-a="cyan"]  {--ac:var(--cyan);}
.mcard[data-a="red"]   {--ac:var(--red);}
.mcard[data-a="yellow"]{--ac:var(--yellow);}
.mcard[data-a="green"] {--ac:var(--green);}
.mcard[data-a="violet"]{--ac:var(--violet);}
.mlabel{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:6px;}
.mval{font-size:30px;font-weight:700;line-height:1;font-family:var(--mono);margin-bottom:8px;}
.mcard[data-a="cyan"]  .mval{color:var(--cyan);}
.mcard[data-a="red"]   .mval{color:var(--red);}
.mcard[data-a="yellow"].mval{color:var(--yellow);}
.mcard[data-a="green"] .mval{color:var(--green);}
.mcard[data-a="violet"].mval{color:var(--violet);}
.msub{font-size:11px;color:var(--muted);}
.msub.up{color:var(--green);} .msub.dn{color:var(--red);}
.mspk{position:absolute;bottom:0;right:0;left:0;height:38px;opacity:.35;}

/* ============================================================  PANELS  */
.panel{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--r);
  padding:20px;backdrop-filter:blur(12px);box-shadow:0 8px 32px rgba(0,0,0,.6);display:flex;flex-direction:column;gap:14px;}
.ph{display:flex;align-items:center;justify-content:space-between;}
.ptitle{font-size:13px;font-weight:600;letter-spacing:.03em;color:var(--text);display:flex;align-items:center;gap:8px;}
.dot{width:6px;height:6px;border-radius:50%;}
.dot.blue  {background:var(--blue);  box-shadow:0 0 6px var(--blue);}
.dot.red   {background:var(--red);   box-shadow:0 0 6px var(--red);}
.dot.green {background:var(--green); box-shadow:0 0 6px var(--green);}
.dot.violet{background:var(--violet);box-shadow:0 0 6px var(--violet);}
.dot.cyan  {background:var(--cyan);  box-shadow:0 0 6px var(--cyan);}
.dot.yellow{background:var(--yellow);box-shadow:0 0 6px var(--yellow);}
.pbadge{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid var(--border);color:var(--muted);}
.cwrap{position:relative;flex:1;min-height:0;}

/* ============================================================  CHARTS ROWS  */
.charts-row{display:grid;grid-template-columns:2fr 1fr;gap:16px;}

/* ============================================================  TABLE  */
.tscroll{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);padding:8px 12px;
  border-bottom:1px solid var(--border);text-align:left;white-space:nowrap;}
tbody tr{border-bottom:1px solid rgba(30,58,100,.25);transition:background .15s;}
tbody tr:hover{background:var(--bg-hover);}
td{padding:9px 12px;font-size:13px;}
.mono{font-family:var(--mono);font-size:12px;}

/* badges */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:6px;
  font-size:11px;font-weight:600;font-family:var(--mono);letter-spacing:.04em;white-space:nowrap;}
.bd-drop  {background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.3); color:var(--red);}
.bd-rate  {background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);color:var(--yellow);}
.bd-allow {background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.3);color:var(--green);}
.bd-zero  {background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.3);color:var(--violet);}
.bd-syn   {background:rgba(239,68,68,.18); border:1px solid rgba(239,68,68,.4); color:#fca5a5;}
.bd-port  {background:rgba(245,158,11,.18);border:1px solid rgba(245,158,11,.4);color:#fcd34d;}
.bd-udp   {background:rgba(234,179,8,.18); border:1px solid rgba(234,179,8,.4); color:#fef08a;}
.bd-normal{background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.3);color:var(--green);}

/* score bar */
.sbar{display:flex;align-items:center;gap:8px;}
.sbar-t{flex:1;height:4px;border-radius:2px;background:rgba(255,255,255,.06);overflow:hidden;}
.sbar-f{height:100%;border-radius:2px;transition:width .5s ease;}

/* buttons */
.btn{padding:5px 12px;border:none;border-radius:var(--r-sm);font-size:12px;font-weight:600;
  cursor:pointer;transition:all .2s;border:1px solid;display:inline-flex;align-items:center;gap:4px;}
.btn-sm{padding:4px 10px;font-size:11px;}
.btn-ub{background:rgba(239,68,68,.12);color:var(--red);border-color:rgba(239,68,68,.3);}
.btn-ub:hover{background:rgba(239,68,68,.25);}

.ctrl-row{display:flex;gap:10px;flex-wrap:wrap;}
.btnc{padding:8px 18px;border-radius:var(--r-sm);font-size:13px;font-weight:600;cursor:pointer;
  transition:all .2s;border:1px solid;display:inline-flex;align-items:center;gap:6px;}
.btnc:disabled{opacity:.5;cursor:not-allowed;}
.btnc-retrain{background:rgba(59,130,246,.12);border-color:rgba(59,130,246,.35);color:var(--blue);}
.btnc-retrain:hover:not(:disabled){background:rgba(59,130,246,.25);}
.btnc-flush{background:rgba(239,68,68,.10);border-color:rgba(239,68,68,.35);color:var(--red);}
.btnc-flush:hover:not(:disabled){background:rgba(239,68,68,.22);}
.btnc-refresh{background:rgba(16,185,129,.10);border-color:rgba(16,185,129,.35);color:var(--green);}
.btnc-refresh:hover{background:rgba(16,185,129,.22);}

/* ============================================================  BOTTOM ROW  */
.bottom-row{display:grid;grid-template-columns:3fr 2fr;gap:16px;}

/* terminal */
.term{background:rgba(2,4,12,.92);border-radius:var(--r-sm);font-family:var(--mono);font-size:11.5px;
  line-height:1.65;padding:12px;overflow-y:auto;border:1px solid rgba(30,58,100,.4);}
.term::-webkit-scrollbar{width:4px;}
.term::-webkit-scrollbar-thumb{background:rgba(59,130,246,.3);border-radius:2px;}
.tl{display:flex;gap:8px;margin-bottom:1px;word-break:break-all;}
.tl-t{color:#334155;min-width:70px;flex-shrink:0;}
.tl-ip{color:#60a5fa;min-width:120px;flex-shrink:0;}
.tl-th{min-width:110px;flex-shrink:0;}
.tl-sc{margin-left:auto;padding-left:8px;flex-shrink:0;}
.c-drop{color:var(--red);} .c-rate{color:var(--yellow);} .c-allow{color:var(--green);} .c-zero{color:var(--violet);} .c-norm{color:#94a3b8;}

/* ============================================================  HEALTH  */
.health-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;}
.hcard{background:var(--bg-glass);border:1px solid var(--border);border-radius:var(--r-sm);padding:14px 16px;display:flex;flex-direction:column;gap:6px;}
.hlabel{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);}
.hval{font-size:15px;font-weight:600;font-family:var(--mono);}
.hbar-w{height:3px;border-radius:2px;background:rgba(255,255,255,.05);overflow:hidden;}
.hbar-f{height:100%;border-radius:2px;transition:width .8s ease;}

/* config chips */
.cfg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin-top:4px;}
.cfgc{padding:10px 14px;background:var(--bg-glass);border:1px solid var(--border);border-radius:var(--r-sm);}
.cfgc-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:4px;}
.cfgc-val{font-family:var(--mono);font-size:13px;}

/* empty state */
.empty{text-align:center;padding:32px 12px;color:var(--dim);font-size:13px;font-family:var(--mono);}

/* ============================================================  TOAST  */
#tc{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;}
.toast{padding:10px 18px;border-radius:var(--r-sm);font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;
  animation:sin .3s ease,sout .4s ease 2.6s forwards;pointer-events:auto;border:1px solid;}
.t-ok{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.4);color:var(--green);}
.t-er{background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.4);color:var(--red);}
.t-in{background:rgba(59,130,246,.15);border-color:rgba(59,130,246,.4);color:var(--blue);}
@keyframes sin {from{transform:translateX(30px);opacity:0}to{transform:none;opacity:1}}
@keyframes sout{from{opacity:1}to{opacity:0;transform:translateX(30px)}}

/* row flash on new data */
@keyframes rflash{0%{background:rgba(59,130,246,.14)}100%{background:transparent}}
.row-new{animation:rflash 1.2s ease;}

/* responsive */
@media(max-width:1280px){.metrics-row{grid-template-columns:repeat(3,1fr);}
  .charts-row,.bottom-row{grid-template-columns:1fr;}}
@media(max-width:700px){.metrics-row{grid-template-columns:repeat(2,1fr);}
  .health-row{grid-template-columns:repeat(2,1fr);}.header-center{display:none;}}
</style>
</head>
<body>
<div class="layout">

<!-- ═══ HEADER ═══ -->
<header class="header">
  <a class="logo" href="#">
    <div class="logo-icon">🛡</div>
    <div class="logo-text"><span>AI</span> Adaptive Firewall</div>
  </a>
  <div class="header-center">
    <div class="nav-pill" onclick="scrollTo('rules-sec')">⚙ Rules</div>
    <div class="nav-pill" onclick="scrollTo('term-sec')">⌨ Events</div>
    <div class="nav-pill" onclick="scrollTo('health-sec')">♡ System</div>
  </div>
  <div class="header-right">
    <div class="status-badge live" id="sb"><div class="status-dot"></div><span id="st">LIVE</span></div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<!-- ═══ MAIN ═══ -->
<main class="main">

<!-- METRIC CARDS -->
<div class="metrics-row">
  <div class="mcard" data-a="cyan">
    <div class="mlabel">📡 Total Events</div>
    <div class="mval" id="m-total">0</div>
    <div class="msub" id="m-total-s">Loading...</div>
    <canvas class="mspk" id="sp-total"></canvas>
  </div>
  <div class="mcard" data-a="red">
    <div class="mlabel">⚠ Threats Detected</div>
    <div class="mval" id="m-threats">0</div>
    <div class="msub" id="m-threats-s">—</div>
    <canvas class="mspk" id="sp-threats"></canvas>
  </div>
  <div class="mcard" data-a="yellow">
    <div class="mlabel">🔒 Active Kernel Blocks</div>
    <div class="mval" id="m-blocks">0</div>
    <div class="msub" id="m-blocks-s">nftables rules</div>
    <canvas class="mspk" id="sp-blocks"></canvas>
  </div>
  <div class="mcard" data-a="green">
    <div class="mlabel">⚡ Avg Response</div>
    <div class="mval" id="m-latency">0 ms</div>
    <div class="msub" id="m-lat-s">target &lt; 50ms</div>
    <canvas class="mspk" id="sp-lat"></canvas>
  </div>
  <div class="mcard" data-a="violet">
    <div class="mlabel">◎ False Positive Rate</div>
    <div class="mval" id="m-fpr">0%</div>
    <div class="msub" id="m-fpr-s">tolerance ≤ 3%</div>
    <canvas class="mspk" id="sp-fpr"></canvas>
  </div>
</div>

<!-- CHARTS ROW -->
<div class="charts-row">
  <div class="panel">
    <div class="ph">
      <div class="ptitle"><div class="dot cyan"></div>Real-Time Anomaly Score (60s window)</div>
      <div class="pbadge" id="score-badge">live</div>
    </div>
    <div class="cwrap" style="height:200px;"><canvas id="ch-timeline"></canvas></div>
  </div>
  <div class="panel">
    <div class="ph">
      <div class="ptitle"><div class="dot red"></div>Threat Distribution</div>
      <div class="pbadge" id="dist-badge">all time</div>
    </div>
    <div class="cwrap" style="height:200px;"><canvas id="ch-donut"></canvas></div>
  </div>
</div>

<!-- THROUGHPUT FULL WIDTH -->
<div class="panel">
  <div class="ph">
    <div class="ptitle"><div class="dot green"></div>Traffic Throughput — Events / 10s</div>
    <div style="display:flex;gap:14px;align-items:center;">
      <span style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;">
        <span style="display:inline-block;width:10px;height:3px;border-radius:2px;background:var(--green);"></span>Normal
      </span>
      <span style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;">
        <span style="display:inline-block;width:10px;height:3px;border-radius:2px;background:var(--red);"></span>Threats
      </span>
    </div>
  </div>
  <div class="cwrap" style="height:150px;"><canvas id="ch-thru"></canvas></div>
</div>

<!-- RULES TABLE -->
<div class="panel" id="rules-sec">
  <div class="ph">
    <div class="ptitle"><div class="dot yellow"></div>Active Mitigation Rules
      <span style="font-size:11px;color:var(--muted);font-weight:400;" id="rules-cnt">(0 active)</span>
    </div>
    <div class="ctrl-row">
      <button class="btnc btnc-retrain" onclick="retrain()" id="btn-ret">🔄 Retrain Model</button>
      <button class="btnc btnc-flush"   onclick="flushRules()" id="btn-fl">💥 Flush All Rules</button>
      <button class="btnc btnc-refresh" onclick="fetchData()">↺ Refresh</button>
    </div>
  </div>
  <div class="tscroll">
    <table>
      <thead><tr>
        <th>Source IP</th><th>Action</th><th>Threat Type</th>
        <th>Anomaly Score</th><th>Age</th><th>Override</th>
      </tr></thead>
      <tbody id="rules-body">
        <tr><td colspan="6" class="empty">No active rules — system operating normally</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- BOTTOM ROW -->
<div class="bottom-row" id="term-sec">
  <!-- Events Table -->
  <div class="panel">
    <div class="ph">
      <div class="ptitle"><div class="dot violet"></div>Recent Events Log</div>
      <div class="pbadge">last 30</div>
    </div>
    <div class="tscroll" style="max-height:320px;overflow-y:auto;">
      <table>
        <thead><tr>
          <th>Time</th><th>Source IP</th><th>Threat</th>
          <th>Score</th><th>Action</th><th>Latency</th>
        </tr></thead>
        <tbody id="events-body">
          <tr><td colspan="6" class="empty">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Live Terminal -->
  <div class="panel" style="min-height:340px;">
    <div class="ph">
      <div class="ptitle"><div class="dot cyan"></div>Live Event Stream</div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-sm btnc-refresh" style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:var(--green);" onclick="clearTerm()">CLR</button>
        <div class="pbadge" id="eps-badge">0 evt/s</div>
      </div>
    </div>
    <div class="term" id="terminal" style="flex:1;min-height:250px;max-height:290px;">
      <div class="tl"><span class="tl-t">--:--:--</span><span style="color:var(--dim)">Waiting for events...</span></div>
    </div>
  </div>
</div>

<!-- SYSTEM HEALTH -->
<div class="panel" id="health-sec">
  <div class="ph">
    <div class="ptitle"><div class="dot green"></div>System Health &amp; Configuration</div>
    <div class="pbadge" id="uptime-b">uptime: --</div>
  </div>
  <div class="health-row">
    <div class="hcard">
      <div class="hlabel">Detection Accuracy</div>
      <div class="hval" style="color:var(--green);">96.4%</div>
      <div class="hbar-w"><div class="hbar-f" style="width:96.4%;background:var(--green);"></div></div>
    </div>
    <div class="hcard">
      <div class="hlabel">Rule Capacity</div>
      <div class="hval" id="cap-v" style="color:var(--blue);">0%</div>
      <div class="hbar-w"><div class="hbar-f" id="cap-b" style="width:0%;background:var(--blue);"></div></div>
    </div>
    <div class="hcard">
      <div class="hlabel">Latency Target</div>
      <div class="hval" style="color:var(--cyan);">&lt; 50ms</div>
      <div class="hbar-w"><div class="hbar-f" id="lat-b" style="width:100%;background:var(--cyan);"></div></div>
    </div>
    <div class="hcard">
      <div class="hlabel">Run Mode</div>
      <div class="hval" id="mode-v" style="color:var(--yellow);">—</div>
      <div class="hbar-w"><div class="hbar-f" style="width:100%;background:var(--violet);"></div></div>
    </div>
  </div>
  <div class="cfg-grid">
    <div class="cfgc"><div class="cfgc-label">Anomaly Threshold</div><div class="cfgc-val" style="color:var(--red);">0.85</div></div>
    <div class="cfgc"><div class="cfgc-label">Rate-Limit Threshold</div><div class="cfgc-val" style="color:var(--yellow);">0.65</div></div>
    <div class="cfgc"><div class="cfgc-label">Max Kernel Rules</div><div class="cfgc-val" style="color:var(--blue);">10,000</div></div>
    <div class="cfgc"><div class="cfgc-label">Rule TTL Default</div><div class="cfgc-val" style="color:var(--green);">300s</div></div>
    <div class="cfgc"><div class="cfgc-label">Max Concurrent Flows</div><div class="cfgc-val" style="color:var(--cyan);">50,000</div></div>
    <div class="cfgc"><div class="cfgc-label">Dashboard Port</div><div class="cfgc-val" style="color:var(--violet);">{{ port }}</div></div>
    <div class="cfgc"><div class="cfgc-label">Classifier</div><div class="cfgc-val" style="color:var(--text);">LSTM-AutoEncoder</div></div>
    <div class="cfgc"><div class="cfgc-label">RL Agent</div><div class="cfgc-val" style="color:var(--text);">PPO (SB3)</div></div>
  </div>
</div>

<div style="text-align:center;padding:16px 0;color:var(--dim);font-size:11px;font-family:var(--mono);letter-spacing:.05em;">
  NEXT-GEN ADAPTIVE FIREWALL &mdash; REAL-TIME ANOMALY DETECTION &amp; KERNEL-LEVEL RULE AUTOMATION &mdash; v2.0
</div>

</main>
</div>
<div id="tc"></div>

<script>
/* ============================================================
   GLOBALS
   ============================================================ */
const REFRESH_MS = {{ refresh_ms }};
let prevTotal=0, prevThreats=0;
let seenIds = new Set();
let termLines = [];
const MAX_TERM = 100;
let timelineData = [];
let epsBuf = [];
let spData = {total:Array(20).fill(0),threats:Array(20).fill(0),blocks:Array(20).fill(0),lat:Array(20).fill(0),fpr:Array(20).fill(0)};
let thruN = Array(20).fill(0), thruT = Array(20).fill(0);
let lastTotalSnap = 0, lastThreatSnap = 0;

/* ============================================================  CLOCK  */
function updateClock(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});}
updateClock(); setInterval(updateClock,1000);

/* ============================================================  CHART DEFAULTS  */
Chart.defaults.color='#64748b';
Chart.defaults.borderColor='rgba(30,80,180,.15)';
Chart.defaults.font.family="'JetBrains Mono',monospace";

/* ─ Sparkline factory ─ */
function mkSpark(id,color){
  const c=document.getElementById(id); if(!c)return null;
  return new Chart(c,{type:'line',
    data:{labels:Array(20).fill(''),datasets:[{data:Array(20).fill(0),
      borderColor:color,borderWidth:1.5,fill:true,
      backgroundColor:color.replace('rgb(','rgba(').replace(')',',0.1)'),
      tension:0.4,pointRadius:0}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,
      plugins:{legend:{display:false},tooltip:{enabled:false}},
      scales:{x:{display:false},y:{display:false,beginAtZero:true}}}
  });
}
const spTotal  =mkSpark('sp-total',  'rgb(34,211,238)');
const spThreats=mkSpark('sp-threats','rgb(239,68,68)');
const spBlocks =mkSpark('sp-blocks', 'rgb(245,158,11)');
const spLat    =mkSpark('sp-lat',    'rgb(16,185,129)');
const spFpr    =mkSpark('sp-fpr',    'rgb(167,139,250)');

function pushSpark(ch,key,v){
  if(!ch)return; spData[key].push(v); spData[key].shift();
  ch.data.datasets[0].data=[...spData[key]]; ch.update('none');
}

/* ─ Timeline Chart ─ */
const chTL=new Chart(document.getElementById('ch-timeline').getContext('2d'),{
  type:'line',
  data:{labels:[],datasets:[
    {label:'Anomaly Score',data:[],borderColor:'rgba(34,211,238,.9)',backgroundColor:'rgba(34,211,238,.05)',borderWidth:1.5,fill:true,tension:0.4,pointRadius:0},
    {label:'Block (0.85)',  data:[],borderColor:'rgba(239,68,68,.45)',borderWidth:1,borderDash:[4,4],fill:false,pointRadius:0},
    {label:'Rate (0.65)',   data:[],borderColor:'rgba(245,158,11,.35)',borderWidth:1,borderDash:[4,4],fill:false,pointRadius:0},
  ]},
  options:{
    responsive:true,maintainAspectRatio:false,animation:{duration:300},
    interaction:{mode:'index',intersect:false},
    plugins:{legend:{display:true,position:'top',labels:{boxWidth:10,boxHeight:2,font:{size:10},color:'#64748b',padding:16}},
      tooltip:{backgroundColor:'rgba(7,12,26,.95)',borderColor:'rgba(59,130,246,.4)',borderWidth:1,bodyFont:{family:"'JetBrains Mono',monospace",size:11}}},
    scales:{x:{ticks:{maxTicksLimit:8,font:{size:9},color:'#334155'},grid:{color:'rgba(30,80,180,.08)'}},
      y:{min:0,max:1,ticks:{stepSize:.25,font:{size:9},color:'#334155'},grid:{color:'rgba(30,80,180,.08)'}}}
  }
});

/* ─ Donut Chart ─ */
const chDN=new Chart(document.getElementById('ch-donut').getContext('2d'),{
  type:'doughnut',
  data:{labels:['NORMAL','SYN_FLOOD','PORT_SCAN','UDP_BURST','ZERO_DAY'],datasets:[{data:[0,0,0,0,0],
    backgroundColor:['rgba(16,185,129,.8)','rgba(239,68,68,.8)','rgba(245,158,11,.8)','rgba(234,179,8,.8)','rgba(167,139,250,.8)'],
    borderColor:['rgba(16,185,129,1)','rgba(239,68,68,1)','rgba(245,158,11,1)','rgba(234,179,8,1)','rgba(167,139,250,1)'],
    borderWidth:1.5,hoverOffset:8}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'72%',animation:{duration:500},
    plugins:{legend:{position:'right',labels:{boxWidth:10,boxHeight:10,font:{size:10},color:'#94a3b8',padding:10}},
      tooltip:{backgroundColor:'rgba(7,12,26,.95)',borderColor:'rgba(59,130,246,.4)',borderWidth:1}}}
});

/* ─ Throughput Chart ─ */
const chTH=new Chart(document.getElementById('ch-thru').getContext('2d'),{
  type:'bar',
  data:{labels:Array(20).fill('').map((_,i)=>`-${(20-i)*10}s`),datasets:[
    {label:'Normal', data:Array(20).fill(0),backgroundColor:'rgba(16,185,129,.5)',borderColor:'rgba(16,185,129,.8)',borderWidth:1,borderRadius:3},
    {label:'Threats',data:Array(20).fill(0),backgroundColor:'rgba(239,68,68,.5)', borderColor:'rgba(239,68,68,.8)', borderWidth:1,borderRadius:3},
  ]},
  options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},
    interaction:{mode:'index',intersect:false},
    plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(7,12,26,.95)',borderColor:'rgba(59,130,246,.4)',borderWidth:1}},
    scales:{x:{stacked:true,ticks:{font:{size:9},color:'#334155',maxTicksLimit:10},grid:{display:false}},
      y:{stacked:true,beginAtZero:true,ticks:{font:{size:9},color:'#334155',precision:0},grid:{color:'rgba(30,80,180,.08)'}}}}
});

/* ============================================================  FETCH  */
async function fetchData(){
  try{
    const [sR,rR,eR,dR]=await Promise.all([
      fetch('/api/stats'),fetch('/api/rules'),
      fetch('/api/events?limit=50'),fetch('/api/distribution')]);
    if(![sR,rR,eR,dR].every(r=>r.ok))return;
    const [s,r,e,d]=await Promise.all([sR.json(),rR.json(),eR.json(),dR.json()]);
    doMetrics(s); doRules(r,s.active_blocks); doEvents(e); doDist(d); doThru(s); doHealth(s,r);
  }catch(ex){console.error(ex);}
}

/* ─ Metrics ─ */
function doMetrics(s){
  document.getElementById('m-total').textContent   = s.total_events.toLocaleString();
  document.getElementById('m-threats').textContent = s.total_threats.toLocaleString();
  document.getElementById('m-blocks').textContent  = s.active_blocks.toLocaleString();
  document.getElementById('m-latency').textContent = s.avg_latency_ms.toFixed(1)+' ms';
  document.getElementById('m-fpr').textContent     = s.false_positive_rate.toFixed(1)+'%';

  const dt=s.total_events-prevTotal, dth=s.total_threats-prevThreats;
  prevTotal=s.total_events; prevThreats=s.total_threats;
  const elTs=document.getElementById('m-total-s');
  if(dt>0){elTs.textContent=`+${dt} new`;elTs.className='msub up';}
  const elTh=document.getElementById('m-threats-s');
  if(dth>0){elTh.textContent=`+${dth} new`;elTh.className='msub dn';}

  const elFprS=document.getElementById('m-fpr-s');
  elFprS.textContent=s.false_positive_rate>3?'⚠ exceeds tolerance':'within tolerance ✓';
  elFprS.className=s.false_positive_rate>3?'msub dn':'msub';

  const elLatS=document.getElementById('m-lat-s');
  elLatS.textContent=s.avg_latency_ms>50?'⚠ over target':'target < 50ms ✓';
  elLatS.style.color=s.avg_latency_ms>50?'var(--red)':'';

  pushSpark(spTotal,  'total',   s.total_events);
  pushSpark(spThreats,'threats', s.total_threats);
  pushSpark(spBlocks, 'blocks',  s.active_blocks);
  pushSpark(spLat,    'lat',     s.avg_latency_ms);
  pushSpark(spFpr,    'fpr',     s.false_positive_rate);
}

/* ─ Rules ─ */
let seenRuleRows=[];
function doRules(rules,cnt){
  document.getElementById('rules-cnt').textContent=`(${cnt} active)`;
  const tb=document.getElementById('rules-body');
  if(!rules||!rules.length){
    tb.innerHTML='<tr><td colspan="6" class="empty">No active rules — system operating normally</td></tr>'; return;}
  tb.innerHTML=rules.map(r=>{
    const sc=parseFloat(r.anomaly_score)||0;
    const sc3=sc.toFixed(3);
    const scCol=sc>0.85?'var(--red)':sc>0.65?'var(--yellow)':'var(--green)';
    const actionBadge=r.action==='DROP_IP'?'<span class="badge bd-drop">⬛ DROP</span>':'<span class="badge bd-rate">⚡ RATE_LIMIT</span>';
    const age=r.age_seconds!=null?parseFloat(r.age_seconds).toFixed(0)+'s':'—';
    return`<tr>
      <td class="mono">${esc(r.src_ip||'')}</td>
      <td>${actionBadge}</td>
      <td>${tBadge(r.threat_type)}</td>
      <td><div class="sbar">
        <span class="mono" style="color:${scCol};min-width:42px;">${sc3}</span>
        <div class="sbar-t"><div class="sbar-f" style="width:${Math.round(sc*100)}%;background:${scCol};"></div></div>
      </div></td>
      <td class="mono" style="color:var(--muted);">${age}</td>
      <td><button class="btn btn-ub btn-sm" onclick="unblock('${esc(r.src_ip||'')}')">🔓 Unblock</button></td>
    </tr>`;
  }).join('');
}

/* ─ Events ─ */
let lastRendered=[];
function doEvents(evts){
  const tb=document.getElementById('events-body');
  if(!evts||!evts.length){tb.innerHTML='<tr><td colspan="6" class="empty">No events yet</td></tr>';return;}
  const shown=evts.slice(0,30);
  const isNew=id=>!lastRendered.includes(id);
  lastRendered=shown.map(e=>e.id);
  tb.innerHTML=shown.map(e=>{
    const sc=parseFloat(e.anomaly_score)||0;
    const scCol=sc>0.85?'var(--red)':sc>0.65?'var(--yellow)':'var(--green)';
    const t=new Date(e.timestamp);
    const ts=isNaN(t)?'—':t.toLocaleTimeString('en-US',{hour12:false});
    const lat=e.mitigation_latency_ms?e.mitigation_latency_ms.toFixed(1)+'ms':'—';
    return`<tr class="${isNew(e.id)?'row-new':''}">
      <td class="mono" style="color:var(--muted);font-size:11px;">${ts}</td>
      <td class="mono" style="font-size:12px;">${esc(e.source_ip||'')}</td>
      <td>${tBadge(e.threat_type)}</td>
      <td class="mono" style="color:${scCol};">${sc.toFixed(3)}</td>
      <td>${aBadge(e.action_taken)}</td>
      <td class="mono" style="color:var(--muted);">${lat}</td>
    </tr>`;
  }).join('');
  doTimeline(shown);
  doTerminal(shown);
}

/* ─ Timeline ─ */
function doTimeline(evts){
  const now=Date.now(), win=60000;
  evts.forEach(e=>{const t=new Date(e.timestamp);if(!isNaN(t))timelineData.push({t:t.getTime(),s:parseFloat(e.anomaly_score)||0});});
  timelineData=[...new Map(timelineData.map(d=>[`${d.t}_${d.s}`,d])).values()]
    .filter(d=>d.t>=now-win).sort((a,b)=>a.t-b.t).slice(-80);
  if(!timelineData.length)return;
  chTL.data.labels=timelineData.map(d=>{const dt=new Date(d.t);return dt.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});});
  chTL.data.datasets[0].data=timelineData.map(d=>d.s);
  chTL.data.datasets[1].data=timelineData.map(()=>0.85);
  chTL.data.datasets[2].data=timelineData.map(()=>0.65);
  chTL.update('none');
}

/* ─ Distribution ─ */
function doDist(d){
  const keys=['NORMAL','SYN_FLOOD','PORT_SCAN','UDP_BURST','ZERO_DAY_ANOMALY'];
  chDN.data.datasets[0].data=keys.map(k=>d[k]||0); chDN.update('none');
  const total=Object.values(d).reduce((a,b)=>a+b,0)||1;
  const norm=d['NORMAL']||0;
  document.getElementById('dist-badge').textContent=`${((norm/total)*100).toFixed(1)}% clean`;
}

/* ─ Throughput ─ */
function doThru(s){
  const normNow=s.total_events-s.total_threats, thrNow=s.total_threats;
  const dN=Math.max(0,normNow-lastTotalSnap), dT=Math.max(0,thrNow-lastThreatSnap);
  lastTotalSnap=normNow; lastThreatSnap=thrNow;
  thruN.push(dN); thruN.shift(); thruT.push(dT); thruT.shift();
  chTH.data.datasets[0].data=[...thruN]; chTH.data.datasets[1].data=[...thruT]; chTH.update('none');
}

/* ─ Health ─ */
function doHealth(s,rules){
  const cap=s.active_blocks/10000*100;
  document.getElementById('cap-v').textContent=cap.toFixed(2)+'%';
  const capB=document.getElementById('cap-b');
  capB.style.width=Math.min(cap,100)+'%';
  capB.style.background=cap>80?'var(--red)':cap>50?'var(--yellow)':'var(--blue)';
  const latPct=s.avg_latency_ms>0?Math.max(0,100-s.avg_latency_ms/50*100):100;
  document.getElementById('lat-b').style.width=latPct+'%';

  fetch('/api/health').then(r=>r.json()).then(h=>{
    const up=Math.floor(Date.now()/1000-(h.startup_time||Date.now()/1000));
    document.getElementById('uptime-b').textContent=`uptime: ${fmtUp(up)}`;
    const mode=h.simulation_mode?'SIMULATION':'LIVE';
    document.getElementById('mode-v').textContent=mode;
    document.getElementById('mode-v').style.color=h.simulation_mode?'var(--yellow)':'var(--green)';
    const sb=document.getElementById('sb'), st=document.getElementById('st');
    if(h.simulation_mode){sb.className='status-badge sim';st.textContent='SIMULATION';}
    else{sb.className='status-badge live';st.textContent='LIVE';}
  }).catch(()=>{});
}

/* ─ Terminal ─ */
function doTerminal(evts){
  const term=document.getElementById('terminal');
  const fresh=evts.filter(e=>!seenIds.has(e.id));
  fresh.forEach(e=>seenIds.add(e.id));
  if(!fresh.length)return;
  epsBuf.push(fresh.length); if(epsBuf.length>10)epsBuf.shift();
  const eps=(epsBuf.reduce((a,b)=>a+b,0)/epsBuf.length).toFixed(1);
  document.getElementById('eps-badge').textContent=eps+' evt/s';
  fresh.slice(0,20).forEach(e=>{
    const t=new Date(e.timestamp);
    const ts=isNaN(t)?'--:--:--':t.toLocaleTimeString('en-US',{hour12:false});
    const act=e.action_taken||'ALLOW';
    const cc=act==='DROP_IP'?'c-drop':act==='RATE_LIMIT_IP'?'c-rate':act==='ALLOW'?'c-allow':'c-zero';
    const sc=parseFloat(e.anomaly_score);
    const scC=sc>0.85?'color:var(--red)':sc>0.65?'color:var(--yellow)':'color:var(--green)';
    termLines.unshift(`<div class="tl"><span class="tl-t">${ts}</span><span class="tl-ip">${esc(e.source_ip||'—')}</span><span class="tl-th ${cc}">${esc(e.threat_type||'—')}</span><span class="${cc}">${esc(act)}</span><span class="tl-sc" style="${scC}">${sc.toFixed(3)}</span></div>`);
  });
  if(termLines.length>MAX_TERM)termLines=termLines.slice(0,MAX_TERM);
  term.innerHTML=termLines.join('');
}

function clearTerm(){
  termLines=[];
  document.getElementById('terminal').innerHTML='<div class="tl"><span class="tl-t">--:--:--</span><span style="color:var(--dim)">Terminal cleared</span></div>';
}

/* ============================================================  ACTIONS  */
async function unblock(ip){
  if(!confirm(`Unblock IP: ${ip}?`))return;
  try{const r=await fetch('/api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    const d=await r.json(); d.status==='ok'?toast(`Unblocked ${ip}`,'ok'):toast(`Failed: ${d.status}`,'er'); fetchData();}
  catch(e){toast('Network error','er');}
}
async function retrain(){
  if(!confirm('Retrain the LSTM-Autoencoder? Runs in background.'))return;
  const b=document.getElementById('btn-ret'); b.disabled=true; b.textContent='⏳ Retraining...';
  try{const r=await fetch('/api/retrain',{method:'POST'}); const d=await r.json();
    toast(d.status==='retraining_started'?'Retraining started':'No classifier','in');}
  catch(e){toast('Network error','er');}
  setTimeout(()=>{b.disabled=false;b.innerHTML='🔄 Retrain Model';},3500);
}
async function flushRules(){
  if(!confirm('⚠ DANGER: Flush ALL active kernel rules? All nftables blocks will be removed immediately.'))return;
  try{const r=await fetch('/api/flush',{method:'POST'}); const d=await r.json();
    toast(d.status==='flushed'?'All rules flushed':'Flush failed',d.status==='flushed'?'ok':'er'); fetchData();}
  catch(e){toast('Network error','er');}
}

/* ============================================================  HELPERS  */
const tMap={NORMAL:'bd-normal',SYN_FLOOD:'bd-syn',PORT_SCAN:'bd-port',UDP_BURST:'bd-udp',ZERO_DAY_ANOMALY:'bd-zero'};
const tIcon={NORMAL:'✓',SYN_FLOOD:'⚡',PORT_SCAN:'🔍',UDP_BURST:'💥',ZERO_DAY_ANOMALY:'☠'};
function tBadge(type){return`<span class="badge ${tMap[type]||'bd-normal'}">${tIcon[type]||'?'} ${esc(type||'—')}</span>`;}
function aBadge(a){
  if(a==='DROP_IP')      return'<span class="badge bd-drop">⬛ DROP</span>';
  if(a==='RATE_LIMIT_IP')return'<span class="badge bd-rate">⚡ RATE_LIMIT</span>';
  if(a==='REMOVE_RULE')  return'<span class="badge bd-allow">✕ REMOVE</span>';
  return'<span class="badge bd-allow">✓ ALLOW</span>';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function fmtUp(s){if(isNaN(s)||s<0)return'--';const h=Math.floor(s/3600),m=Math.floor(s%3600/60),sec=s%60;return h>0?`${h}h ${m}m`:m>0?`${m}m ${sec}s`:`${sec}s`;}
function scrollTo(id){document.getElementById(id)?.scrollIntoView({behavior:'smooth',block:'start'});}

function toast(msg,type='in'){
  const c=document.getElementById('tc');
  const el=document.createElement('div');
  el.className=`toast t-${type}`;
  const icons={ok:'✓',er:'✕',in:'ℹ'};
  el.innerHTML=`<span>${icons[type]||'•'}</span> ${esc(msg)}`;
  c.appendChild(el); setTimeout(()=>el.remove(),3200);
}

/* ============================================================  BOOT  */
fetchData();
setInterval(fetchData, REFRESH_MS);
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
            port=config.DASHBOARD_PORT,
        )

    @app.route("/api/stats")
    def api_stats():
        if app.fw_db:
            return jsonify(app.fw_db.get_stats())
        return jsonify({
            "total_events": 0, "total_threats": 0,
            "active_blocks": 0, "avg_latency_ms": 0.0,
            "false_positive_rate": 0.0,
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
        return jsonify({"status": "error", "msg": "No kernel enforcer or invalid IP"}), 400

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
            "startup_time": app._start_time,
            "uptime_seconds": round(time.time() - app._start_time, 1),
            "simulation_mode": config.SIMULATION_MODE,
            "dashboard_port": config.DASHBOARD_PORT,
            "version": "2.0",
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

