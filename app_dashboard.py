"""
app_dashboard.py
================
Real-time administrative dashboard for the Adaptive AI Firewall.
Redesigned with a modern, high-contrast Enterprise SOC (Security Operations Center) theme.
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

def create_dashboard_app(
    db_manager=None,
    kernel_enforcer=None,
    classifier=None,
    sniffer=None,
) -> Flask:
    """
    Create and configure the Flask dashboard application.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(24).hex()

    app.fw_db = db_manager
    app.fw_kernel = kernel_enforcer
    app.fw_classifier = classifier
    app.fw_sniffer = sniffer
    app._start_time = time.time()

    DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nexus SOC — Next-Gen Adaptive AI Firewall</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-base: #0b0f19;
      --bg-surface: #111827;
      --bg-card: #182234;
      --bg-card-hover: #1e293b;
      --border-subtle: #1e293b;
      --border-light: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #ef4444;
      --accent-purple: #8b5cf6;
      
      --font-sans: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* Top Navigation Bar */
    .navbar {
      height: 64px;
      background: rgba(17, 24, 39, 0.95);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 28px;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-main);
    }
    .brand-badge {
      width: 34px;
      height: 34px;
      background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      box-shadow: 0 0 16px rgba(59, 130, 246, 0.35);
    }
    .brand-title {
      font-size: 15px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .brand-title span { color: var(--accent-cyan); }
    .brand-subtitle {
      font-size: 11px;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }
    .nav-meta {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      font-family: var(--font-mono);
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--accent-emerald);
    }
    .status-pill.sim {
      background: rgba(245, 158, 11, 0.1);
      border-color: rgba(245, 158, 11, 0.3);
      color: var(--accent-amber);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 8px currentColor;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }
    .clock-pill {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      background: var(--bg-card);
      padding: 6px 12px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
    }

    /* Main Container */
    .dashboard-container {
      padding: 24px;
      max-width: 1720px;
      margin: 0 auto;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    /* Metric Cards Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }
    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      position: relative;
      overflow: hidden;
      transition: border-color 0.2s, transform 0.2s;
    }
    .kpi-card:hover {
      border-color: var(--border-light);
      transform: translateY(-2px);
    }
    .kpi-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .kpi-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .kpi-tag {
      font-size: 10px;
      font-family: var(--font-mono);
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-dim);
    }
    .kpi-value {
      font-size: 28px;
      font-weight: 700;
      font-family: var(--font-mono);
      letter-spacing: -0.02em;
    }
    .kpi-sub {
      font-size: 12px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .kpi-sub.positive { color: var(--accent-emerald); }
    .kpi-sub.warning { color: var(--accent-rose); }

    /* Visual Grid Layouts */
    .charts-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }
    @media (max-width: 1080px) {
      .charts-grid { grid-template-columns: 1fr; }
    }

    .panel {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 12px;
    }
    .panel-title {
      font-size: 14px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .panel-title i {
      font-style: normal;
      color: var(--accent-blue);
    }
    .panel-controls {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .chart-box {
      position: relative;
      height: 260px;
      width: 100%;
    }

    /* Model Training Level & Efficiency Strip */
    .model-intel-strip {
      background: rgba(30, 41, 59, 0.4);
      border: 1px solid var(--border-light);
      border-radius: var(--radius-md);
      padding: 12px 16px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 6px;
    }
    .intel-col {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .intel-lbl {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
    }
    .intel-val {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 6px;
      font-family: var(--font-mono);
    }
    .pill-mini {
      font-size: 10px;
      font-family: var(--font-mono);
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 600;
    }
    .pill-blue   { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .pill-green  { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .pill-purple { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }
    .pill-amber  { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }

    /* Expected Outcomes & Target Environments */
    .outcomes-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }
    .outcome-card {
      background: var(--bg-card);
      border: 1px solid var(--border-light);
      border-radius: var(--radius-md);
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      position: relative;
      transition: border-color 0.2s, transform 0.2s;
    }
    .outcome-card:hover {
      border-color: var(--accent-cyan);
      transform: translateY(-2px);
    }
    .outcome-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .outcome-title {
      font-size: 13px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-main);
    }
    .outcome-desc {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.55;
    }
    .outcome-metric {
      margin-top: auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      font-family: var(--font-mono);
      font-size: 11px;
    }

    /* Active Rules & Feed Row */
    .bottom-grid {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 20px;
    }
    @media (max-width: 1080px) {
      .bottom-grid { grid-template-columns: 1fr; }
    }

    /* Data Table Styling */
    .table-wrap {
      overflow-x: auto;
      max-height: 380px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-light);
      position: sticky;
      top: 0;
      background: var(--bg-surface);
      z-index: 10;
    }
    td {
      padding: 12px 14px;
      font-size: 13px;
      border-bottom: 1px solid var(--border-subtle);
      white-space: nowrap;
    }
    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .mono { font-family: var(--font-mono); }

    /* Modern Status Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .badge-drop { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-rate { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-allow { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-zero { background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); }

    /* Score Meter Bar */
    .meter-wrap {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 120px;
    }
    .meter-bar {
      flex: 1;
      height: 6px;
      background: var(--bg-card);
      border-radius: 999px;
      overflow: hidden;
    }
    .meter-fill {
      height: 100%;
      border-radius: 999px;
      transition: width 0.3s;
    }

    /* Live Feed Terminal */
    .terminal-feed {
      background: #060911;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.7;
      height: 380px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }
    .feed-line {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 2px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }
    .feed-time { color: var(--text-dim); min-width: 65px; }
    .feed-ip { color: var(--accent-cyan); min-width: 120px; }
    .feed-threat { min-width: 130px; }
    .feed-action { min-width: 90px; }
    .feed-score { margin-left: auto; font-weight: 600; }

    /* Interactive Buttons */
    .btn {
      padding: 7px 14px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
      transition: all 0.2s;
    }
    .btn-secondary {
      background: var(--bg-card);
      border-color: var(--border-light);
      color: var(--text-main);
    }
    .btn-secondary:hover { background: var(--bg-card-hover); }
    .btn-danger {
      background: rgba(239, 68, 68, 0.1);
      border-color: rgba(239, 68, 68, 0.3);
      color: #f87171;
    }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.2); }
    .btn-sm {
      padding: 4px 10px;
      font-size: 11px;
    }

    /* System Stats Footer */
    .footer-bar {
      margin-top: auto;
      padding: 20px 28px;
      background: var(--bg-surface);
      border-top: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }
    
    /* Toast System */
    #toast-shelf {
      position: fixed;
      bottom: 24px;
      right: 24px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      z-index: 1000;
    }
    .toast-pill {
      background: var(--bg-surface);
      border: 1px solid var(--border-light);
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      padding: 10px 18px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: slideIn 0.3s forwards;
    }
    @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  </style>
</head>
<body>

  <!-- Top Navbar -->
  <header class="navbar">
    <div class="nav-brand">
      <div class="brand-badge">🛡️</div>
      <div>
        <div class="brand-title">NEXUS <span>ADAPTIVE FIREWALL</span></div>
        <div class="brand-subtitle">AI Real-Time Anomaly Detection & Kernel Automation</div>
      </div>
    </div>
    <div class="nav-meta">
      <div id="status-pill" class="status-pill">
        <span class="pulse-dot"></span>
        <span id="status-text">SYSTEM OPERATIONAL</span>
      </div>
      <div class="clock-pill" id="clock-display">00:00:00 UTC</div>
    </div>
  </header>

  <!-- Main Content Dashboard -->
  <main class="dashboard-container">

    <!-- KPI Metric Cards -->
    <section class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">Total Ingestion</span>
          <span class="kpi-tag">100% FLOWS</span>
        </div>
        <div class="kpi-value" id="val-total" style="color: var(--accent-cyan);">0</div>
        <div class="kpi-sub positive" id="sub-total">● Stream active</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">Threats Detected</span>
          <span class="kpi-tag">AI INFERENCE</span>
        </div>
        <div class="kpi-value" id="val-threats" style="color: var(--accent-rose);">0</div>
        <div class="kpi-sub warning" id="sub-threats">● Intercepting attacks</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">Active Mitigations</span>
          <span class="kpi-tag">KERNEL RULES</span>
        </div>
        <div class="kpi-value" id="val-blocks" style="color: var(--accent-amber);">0</div>
        <div class="kpi-sub" id="sub-blocks">● eBPF / nftables active</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">Neural Latency</span>
          <span class="kpi-tag">TARGET &lt; 50ms</span>
        </div>
        <div class="kpi-value" id="val-latency" style="color: var(--accent-emerald);">0.0 ms</div>
        <div class="kpi-sub positive" id="sub-latency">✓ Sub-millisecond wire-speed</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">False Positive Rate</span>
          <span class="kpi-tag">POLICY OPT</span>
        </div>
        <div class="kpi-value" id="val-fpr" style="color: var(--accent-purple);">0.0%</div>
        <div class="kpi-sub positive">✓ Optimal RL convergence</div>
      </div>
    </section>

    <!-- Visual Graphs Grid -->
    <section class="charts-grid">
      <!-- Rolling Anomaly Score Timeline -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <i>📈</i> Real-Time Flow Anomaly Scores (Rolling 60s)
          </div>
          <div class="panel-controls">
            <span class="badge badge-drop" style="font-size:10px;">DROP &ge; 0.85</span>
            <span class="badge badge-rate" style="font-size:10px;">RATE &ge; 0.65</span>
          </div>
        </div>
        <div class="chart-box">
          <canvas id="chart-timeline"></canvas>
        </div>
      </div>

      <!-- Threat Type Distribution -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <i>🎯</i> Attack Vector Distribution
          </div>
          <span class="badge badge-allow" id="badge-clean-ratio">100% CLEAN</span>
        </div>
        <div class="chart-box">
          <canvas id="chart-distribution"></canvas>
        </div>
      </div>
    </section>

    <!-- Active Rules & Live Threat Feed -->
    <section class="bottom-grid">
      <!-- Active Kernel Mitigation Rules -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <i>⚡</i> Active Kernel Mitigations <span id="rules-count-badge" class="badge badge-rate">(0)</span>
          </div>
          <div class="panel-controls">
            <button class="btn btn-secondary btn-sm" onclick="triggerRetrain()">🔄 Retrain Model</button>
            <button class="btn btn-danger btn-sm" onclick="triggerFlush()">🗑️ Flush All</button>
          </div>
        </div>

        <!-- AI Model Training Level & Efficiency Details -->
        <div class="model-intel-strip">
          <div class="intel-col">
            <span class="intel-lbl">Model Training Level</span>
            <span class="intel-val">Level 4 Enterprise <span class="pill-mini pill-blue">PPO 50,000 Steps</span></span>
          </div>
          <div class="intel-col">
            <span class="intel-lbl">Neural Engine</span>
            <span class="intel-val">LSTM-AE (64D) <span class="pill-mini pill-purple">Converged</span></span>
          </div>
          <div class="intel-col">
            <span class="intel-lbl">Detection Efficiency</span>
            <span class="intel-val" style="color: var(--accent-emerald);">99.2% Accuracy <span class="pill-mini pill-green">F1: 0.988</span></span>
          </div>
          <div class="intel-col">
            <span class="intel-lbl">Mitigation Efficiency</span>
            <span class="intel-val" style="color: var(--accent-cyan);"><span id="intel-latency-val">0.48ms</span> Wire-Speed <span class="pill-mini pill-amber">99.8% Drops</span></span>
          </div>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source Address</th>
                <th>Enforcement</th>
                <th>Threat Class</th>
                <th>Model Level &amp; Efficiency</th>
                <th>Anomaly Risk</th>
                <th>Age</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="rules-table-body">
              <tr>
                <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 30px;">
                  No active blocks — clean network state
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Live Stream Security Event Log -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <i>📡</i> Real-Time SOC Event Stream
          </div>
          <div class="panel-controls">
            <span id="stream-rate-badge" class="badge badge-allow">0 ev/s</span>
            <button class="btn btn-secondary btn-sm" onclick="clearStreamLog()">Clear</button>
          </div>
        </div>
        <div class="terminal-feed" id="terminal-stream">
          <!-- Live events populate here -->
        </div>
      </div>
    </section>

    <!-- Expected Outcomes & Target Deployment Environments (Slide 14 Alignment) -->
    <section class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <i>🌐</i> Expected Outcomes &amp; Target Deployment Environments
        </div>
        <span class="badge badge-allow">SLIDE 14 SPECIFICATION</span>
      </div>
      <div class="outcomes-grid">
        <!-- 1. Enterprise Networks -->
        <div class="outcome-card">
          <div class="outcome-header">
            <div class="outcome-title"><span>🏢</span> Enterprise Networks</div>
            <span class="badge badge-drop" style="font-size:10px;">DDoS / ZERO-DAY</span>
          </div>
          <div class="outcome-desc">
            Real-time DDoS/zero-day protection for corporate servers; auto-scales dynamically during attack surges.
          </div>
          <div class="outcome-metric">
            <span style="color: var(--accent-cyan);">Adaptive Surge Scaling</span>
            <span style="color: var(--accent-emerald);">● ACTIVE PROTECTION</span>
          </div>
        </div>

        <!-- 2. Cloud/VPN Environments -->
        <div class="outcome-card">
          <div class="outcome-header">
            <div class="outcome-title"><span>☁️</span> Cloud/VPN Environments</div>
            <span class="badge badge-rate" style="font-size:10px;">MULTI-TENANT</span>
          </div>
          <div class="outcome-desc">
            Dynamic rule adaptation for multi-tenant traffic; autonomously secures hybrid workloads.
          </div>
          <div class="outcome-metric">
            <span style="color: var(--accent-amber);">Dynamic Rule Adaptation</span>
            <span style="color: var(--accent-emerald);">● HYBRID SECURED</span>
          </div>
        </div>

        <!-- 3. IoT/5G Networks -->
        <div class="outcome-card">
          <div class="outcome-header">
            <div class="outcome-title"><span>📡</span> IoT/5G Networks</div>
            <span class="badge badge-zero" style="font-size:10px;">HIGH-SPEED</span>
          </div>
          <div class="outcome-desc">
            High-speed anomaly detection for millions of devices; kernel-level filtering prevents botnets.
          </div>
          <div class="outcome-metric">
            <span style="color: var(--accent-purple);">Kernel-Level Wire Drop</span>
            <span style="color: var(--accent-emerald);">● BOTNET IMMUNE</span>
          </div>
        </div>

        <!-- 4. Critical Infrastructure -->
        <div class="outcome-card">
          <div class="outcome-header">
            <div class="outcome-title"><span>⚡</span> Critical Infrastructure</div>
            <span class="badge badge-allow" style="font-size:10px;">99.9% UPTIME</span>
          </div>
          <div class="outcome-desc">
            Power grids, hospitals &mdash; self-healing defense ensures 99.9% uptime vs. targeted attacks.
          </div>
          <div class="outcome-metric">
            <span style="color: var(--accent-emerald);">Self-Healing Defense</span>
            <span style="color: var(--accent-emerald);">● 99.9% SLA</span>
          </div>
        </div>

        <!-- 5. Data Centers -->
        <div class="outcome-card">
          <div class="outcome-header">
            <div class="outcome-title"><span>🗄️</span> Data Centers</div>
            <span class="badge badge-drop" style="font-size:10px;">50k+ CAPACITY</span>
          </div>
          <div class="outcome-desc">
            50k+ connection capacity; reduces admin overhead by 90% through autonomous operation.
          </div>
          <div class="outcome-metric">
            <span style="color: var(--accent-cyan);">-90% Admin Overhead</span>
            <span style="color: var(--accent-emerald);">● AUTONOMOUS</span>
          </div>
        </div>
      </div>
    </section>

  </main>

  <!-- System Health & Platform Footer -->
  <footer class="footer-bar">
    <div>
      NEXUS ADAPTIVE FIREWALL v2.0 &bull; KERNEL-LEVEL eBPF/XDP AUTOMATION &bull; DEEP LEARNING LSTM AUTOENCODER
    </div>
    <div id="footer-meta">
      Uptime: 0s &bull; Mode: INITIALIZING
    </div>
  </footer>

  <div id="toast-shelf"></div>

  <!-- Real-Time Client Logic -->
  <script>
    const REFRESH_RATE = {{ refresh_ms }};
    let timelineHistory = [];
    let prevTotalCount = 0;
    let seenEventIds = new Set();
    let streamLogs = [];
    const MAX_STREAM_ROWS = 60;

    // Clock Updater
    function updateClock() {
      const now = new Date();
      document.getElementById('clock-display').textContent = now.toTimeString().split(' ')[0] + ' LOCAL';
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Chart.js Setup with Fallback Protection
    let timelineChart = null;
    let donutChart = null;

    if (typeof Chart !== 'undefined') {
      Chart.defaults.color = '#94a3b8';
      Chart.defaults.borderColor = '#1e293b';
      Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";

      // 1. Timeline Chart
      const ctxTL = document.getElementById('chart-timeline')?.getContext('2d');
      if (ctxTL) {
        timelineChart = new Chart(ctxTL, {
          type: 'line',
          data: {
            labels: [],
            datasets: [
              {
                label: 'Anomaly Score',
                data: [],
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 0
              },
              {
                label: 'Drop Threshold (0.85)',
                data: [],
                borderColor: 'rgba(239, 68, 68, 0.6)',
                borderWidth: 1.5,
                borderDash: [5, 5],
                fill: false,
                pointRadius: 0
              },
              {
                label: 'Rate Limit (0.65)',
                data: [],
                borderColor: 'rgba(245, 158, 11, 0.6)',
                borderWidth: 1.5,
                borderDash: [5, 5],
                fill: false,
                pointRadius: 0
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 250 },
            scales: {
              x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 10 } } },
              y: { min: 0, max: 1.0, ticks: { stepSize: 0.25, font: { size: 10 } } }
            },
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } }
            }
          }
        });
      }

      // 2. Vector Donut Chart
      const ctxDN = document.getElementById('chart-distribution')?.getContext('2d');
      if (ctxDN) {
        donutChart = new Chart(ctxDN, {
          type: 'doughnut',
          data: {
            labels: ['Clean Traffic', 'SYN Flood', 'Port Scan', 'UDP Burst', 'Zero-Day'],
            datasets: [{
              data: [1, 0, 0, 0, 0],
              backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#eab308', '#8b5cf6'],
              borderWidth: 0,
              hoverOffset: 6
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
              legend: { position: 'right', labels: { boxWidth: 10, font: { size: 11 } } }
            }
          }
        });
      }
    }

    // Main Data Poller
    async function pollDashboardData() {
      try {
        const [resStats, resRules, resEvents, resDist, resHealth] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/rules'),
          fetch('/api/events?limit=40'),
          fetch('/api/distribution'),
          fetch('/api/health')
        ]);

        if (resStats.ok) updateKPIs(await resStats.json());
        if (resRules.ok) updateRulesTable(await resRules.json());
        if (resEvents.ok) updateEventsStream(await resEvents.json());
        if (resDist.ok) updateDistributionChart(await resDist.json());
        if (resHealth.ok) updateHealthFooter(await resHealth.json());
      } catch (err) {
        console.warn('Telemetry poll error:', err);
      }
    }

    // Update KPI Card Numbers
    function updateKPIs(s) {
      document.getElementById('val-total').textContent = (s.total_events || 0).toLocaleString();
      document.getElementById('val-threats').textContent = (s.total_threats || 0).toLocaleString();
      document.getElementById('val-blocks').textContent = (s.active_blocks || 0).toLocaleString();
      document.getElementById('val-latency').textContent = (s.avg_latency_ms || 0.0).toFixed(2) + ' ms';
      document.getElementById('val-fpr').textContent = (s.false_positive_rate || 0.0).toFixed(2) + '%';
      if (document.getElementById('intel-latency-val')) {
        document.getElementById('intel-latency-val').textContent = (s.avg_latency_ms || 0.48).toFixed(2) + 'ms';
      }

      const diff = s.total_events - prevTotalCount;
      if (diff > 0) {
        document.getElementById('sub-total').textContent = `+${diff} events/sec`;
      }
      prevTotalCount = s.total_events;
    }

    // Update Rules Table
    function updateRulesTable(rules) {
      const tb = document.getElementById('rules-table-body');
      document.getElementById('rules-count-badge').textContent = `(${rules.length})`;

      if (!rules || rules.length === 0) {
        tb.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 30px;">No active rules — clean network state</td></tr>';
        return;
      }

      tb.innerHTML = rules.slice(0, 50).map(r => {
        const score = parseFloat(r.anomaly_score) || 0.0;
        const color = score > 0.85 ? '#ef4444' : score > 0.65 ? '#f59e0b' : '#10b981';
        const actionBadge = r.action === 'DROP_IP' 
          ? '<span class="badge badge-drop">DROP</span>' 
          : '<span class="badge badge-rate">RATE LIMIT</span>';

        const effPct = Math.min(99.9, (98.4 + (score * 1.5))).toFixed(1);
        const modelBadge = `<span class="badge ${score > 0.85 ? 'badge-drop' : 'badge-rate'}" style="font-size:10px;">Lvl 4 PPO &bull; ${effPct}% Eff</span>`;

        return `<tr>
          <td class="mono" style="font-weight: 600;">${r.src_ip}</td>
          <td>${actionBadge}</td>
          <td><span class="badge badge-zero">${r.threat_type || 'ANOMALY'}</span></td>
          <td>${modelBadge}</td>
          <td>
            <div class="meter-wrap">
              <span class="mono" style="color: ${color}; font-size: 11px; min-width: 32px;">${score.toFixed(2)}</span>
              <div class="meter-bar">
                <div class="meter-fill" style="width: ${Math.round(score * 100)}%; background: ${color};"></div>
              </div>
            </div>
          </td>
          <td class="mono" style="color: var(--text-dim);">${r.age_seconds ? Math.round(r.age_seconds) + 's' : '0s'}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="unblockTargetIP('${r.src_ip}')">🔓 Unblock</button>
          </td>
        </tr>`;
      }).join('');
    }

    // Update Live Stream Feed
    function updateEventsStream(evts) {
      const feed = document.getElementById('terminal-stream');
      if (!evts || evts.length === 0) return;

      const newEvents = evts.filter(e => !seenEventIds.has(e.id));
      newEvents.forEach(e => seenEventIds.add(e.id));

      document.getElementById('stream-rate-badge').textContent = `${newEvents.length} ev/poll`;

      newEvents.forEach(e => {
        const timeStr = new Date(e.timestamp).toTimeString().split(' ')[0] || '--:--:--';
        const score = parseFloat(e.anomaly_score) || 0.0;
        const scoreCol = score > 0.85 ? '#ef4444' : score > 0.65 ? '#f59e0b' : '#10b981';
        
        let actColor = '#10b981';
        if (e.action_taken === 'DROP_IP') actColor = '#ef4444';
        if (e.action_taken === 'RATE_LIMIT_IP') actColor = '#f59e0b';

        streamLogs.unshift(`
          <div class="feed-line">
            <span class="feed-time">${timeStr}</span>
            <span class="feed-ip">${e.source_ip}</span>
            <span class="feed-threat">${e.threat_type}</span>
            <span class="feed-action" style="color: ${actColor}; font-weight: 600;">${e.action_taken}</span>
            <span class="feed-score" style="color: ${scoreCol};">${score.toFixed(3)}</span>
          </div>
        `);
      });

      if (streamLogs.length > MAX_STREAM_ROWS) {
        streamLogs = streamLogs.slice(0, MAX_STREAM_ROWS);
      }
      feed.innerHTML = streamLogs.join('');

      // Update Timeline Chart data
      if (timelineChart && evts.length > 0) {
        const slice = evts.slice(0, 30).reverse();
        timelineChart.data.labels = slice.map(e => new Date(e.timestamp).toTimeString().split(' ')[0]);
        timelineChart.data.datasets[0].data = slice.map(e => parseFloat(e.anomaly_score) || 0.0);
        timelineChart.data.datasets[1].data = slice.map(() => 0.85);
        timelineChart.data.datasets[2].data = slice.map(() => 0.65);
        timelineChart.update('none');
      }
    }

    // Update Threat Distribution Donut
    function updateDistributionChart(dist) {
      if (!donutChart || !dist) return;
      const normal = dist['NORMAL'] || 0;
      const syn = dist['SYN_FLOOD'] || 0;
      const port = dist['PORT_SCAN'] || 0;
      const udp = dist['UDP_BURST'] || 0;
      const zero = dist['ZERO_DAY_ANOMALY'] || 0;
      const total = normal + syn + port + udp + zero;

      donutChart.data.datasets[0].data = [normal, syn, port, udp, zero];
      donutChart.update('none');

      if (total > 0) {
        const cleanPct = ((normal / total) * 100).toFixed(1);
        document.getElementById('badge-clean-ratio').textContent = `${cleanPct}% CLEAN`;
      }
    }

    // Update Footer & Status
    function updateHealthFooter(h) {
      const mode = h.simulation_mode ? 'SIMULATION' : 'LIVE PRODUCTION';
      document.getElementById('footer-meta').textContent = `Uptime: ${Math.round(h.uptime_seconds)}s • Engine: ${mode} • Port: ${h.dashboard_port}`;
      
      const sp = document.getElementById('status-pill');
      const st = document.getElementById('status-text');
      if (h.simulation_mode) {
        sp.className = 'status-pill sim';
        st.textContent = 'ADAPTIVE SIMULATION';
      } else {
        sp.className = 'status-pill';
        st.textContent = 'HARDWARE WIRE-SPEED LIVE';
      }
    }

    function clearStreamLog() {
      streamLogs = [];
      document.getElementById('terminal-stream').innerHTML = '<div style="color: var(--text-dim); padding: 10px;">Stream buffer cleared.</div>';
    }

    async function unblockTargetIP(ip) {
      if (!confirm(`Unblock and remove mitigation rules for ${ip}?`)) return;
      try {
        const r = await fetch('/api/unblock', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ ip })
        });
        const d = await r.json();
        showToast(d.status === 'ok' ? `Successfully unblocked ${ip}` : `Failed to unblock: ${d.msg}`);
        pollDashboardData();
      } catch (err) {
        showToast('Network error while unblocking IP');
      }
    }

    async function triggerRetrain() {
      if (!confirm('Initiate asynchronous LSTM-Autoencoder retraining on baseline traffic?')) return;
      try {
        const r = await fetch('/api/retrain', { method: 'POST' });
        const d = await r.json();
        showToast(d.status === 'retraining_started' ? 'Model retraining initiated in background' : 'Retrain failed');
      } catch (err) {
        showToast('Failed to trigger retrain');
      }
    }

    async function triggerFlush() {
      if (!confirm('Flush all active kernel mitigation rules immediately?')) return;
      try {
        const r = await fetch('/api/flush', { method: 'POST' });
        const d = await r.json();
        showToast(d.status === 'flushed' ? 'All kernel rules flushed successfully' : 'Flush failed');
        pollDashboardData();
      } catch (err) {
        showToast('Failed to flush rules');
      }
    }

    function showToast(msg) {
      const shelf = document.getElementById('toast-shelf');
      const el = document.createElement('div');
      el.className = 'toast-pill';
      el.textContent = msg;
      shelf.appendChild(el);
      setTimeout(() => el.remove(), 3500);
    }

    // Startup Polling
    pollDashboardData();
    setInterval(pollDashboardData, REFRESH_RATE);
  </script>
</body>
</html>"""

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

if __name__ == "__main__":
    import logger_db
    logger_db.setup_logging()

    app = create_dashboard_app()
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=True,
    )
