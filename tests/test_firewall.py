import pytest
import os
import tempfile
import numpy as np
import config
from classifier import AnomalyClassifier
from logger_db import DatabaseManager

def test_config_defaults():
    assert config.DASHBOARD_PORT == 8050
    assert config.FEATURE_DIM == 15
    assert len(config.WHITELIST_IPS) > 0

def test_database_manager():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    try:
        db = DatabaseManager(db_path)
        stats = db.get_stats()
        assert isinstance(stats, dict)
        assert "total_events" in stats
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_classifier_initialization():
    clf = AnomalyClassifier()
    assert clf.model.feature_dim == 15
    assert clf.model.latent_dim == 64

def test_classifier_prediction_shape():
    clf = AnomalyClassifier()
    dummy_features = np.zeros(15, dtype=np.float32)
    score, threat_label, latent = clf.predict(dummy_features)
    assert 0.0 <= score <= 1.0
    assert isinstance(threat_label, str)
    assert latent.shape == (64,)

def test_threat_intelligence():
    from threat_intel import ThreatIntelligenceFeed
    feed = ThreatIntelligenceFeed()
    stats = feed.get_stats()
    assert stats["is_active"] is True
    assert stats["total_tracked"] > 0
    # Check threat multiplier on known malicious IP
    assert feed.check_ip("185.112.98.44") == 2.5
    assert feed.check_ip("192.168.1.1") == 1.0

def test_xai_explainer():
    from xai_explainer import AnomalyExplainer
    explainer = AnomalyExplainer()
    # Test high SYN ratio flow
    dummy = np.zeros((1, 15), dtype=np.float32)
    dummy[0, 13] = 0.95  # SYN ratio
    exp = explainer.explain_anomaly(dummy)
    assert "[XAI]" in exp or "XAI" in exp
    assert "SYN" in exp

def test_dashboard_endpoints():
    from app_dashboard import create_dashboard_app
    app = create_dashboard_app()
    client = app.test_client()

    resp_health = client.get("/api/health")
    assert resp_health.status_code == 200

    resp_sla = client.get("/api/sla")
    assert resp_sla.status_code == 200
    sla_data = resp_sla.get_json()
    assert "metrics" in sla_data

    resp_pipe = client.get("/api/pipeline")
    assert resp_pipe.status_code == 200
    pipe_data = resp_pipe.get_json()
    assert "stages" in pipe_data
    assert len(pipe_data["stages"]) == 5

    resp_threat = client.get("/api/threat-intel")
    assert resp_threat.status_code == 200

    resp_self = client.get("/api/self-healing")
    assert resp_self.status_code == 200

    resp_base = client.get("/api/baseline")
    assert resp_base.status_code == 200

    resp_mitre = client.get("/api/mitre")
    assert resp_mitre.status_code == 200
    assert "tactics" in resp_mitre.get_json()

    resp_export = client.get("/api/export-incident-report")
    assert resp_export.status_code == 200
    export_data = resp_export.get_json()
    assert "sha256_cryptographic_audit_signature" in export_data

def test_geo_intelligence():
    from geo_intel import GeoIPIntelligence
    geo = GeoIPIntelligence()
    res_ru = geo.lookup("185.112.98.44")
    assert res_ru["cc"] == "RU"
    assert res_ru["flag"] == "🇷🇺"
    assert "Selectel" in res_ru["org"]

    res_lan = geo.lookup("192.168.1.50")
    assert res_lan["cc"] == "LAN"

def test_mitre_mapping():
    from mitre_mapper import MitreAttackMapper
    m = MitreAttackMapper()
    syn_map = m.map_threat("SYN_FLOOD")
    assert syn_map["technique_id"] == "T1498.001"
    assert syn_map["tactic"] == "Impact"

    scan_map = m.map_threat("PORT_SCAN")
    assert scan_map["technique_id"] == "T1046"

    all_tactics = m.get_all_matrix_tactics()
    assert len(all_tactics) >= 5

def test_cyberattack_simulator():
    from attack_generator import CyberAttackSimulator
    sim = CyberAttackSimulator()
    status = sim.get_status()
    assert status["is_active"] is False

    vec = sim._synthesize_attack_vector("SYN_FLOOD")
    assert len(vec) == 15
    assert vec[13] > 0.9  # SYN flag ratio > 90%

def test_port_sentinel():
    from port_sentinel import PortSentinel
    ps = PortSentinel()
    ports = ps.scan_ports()
    assert len(ports) > 0
    p80 = next((p for p in ports if p["port"] == 80), None)
    assert p80 is not None
    assert "HTTP" in p80["service"]
    assert "description" in p80

    # Test closing port
    close_res = ps.close_port(80, "TCP")
    assert close_res["success"] is True
    assert close_res["status"] == "CLOSED"

    # Search for port 80
    search_res = ps.search(query="80")
    assert any(p["port"] == 80 for p in search_res)

    # Re-open port 80
    open_res = ps.open_port(80, "TCP")
    assert open_res["success"] is True
    assert open_res["status"] == "OPEN"

def test_port_endpoints():
    from app_dashboard import create_dashboard_app
    app = create_dashboard_app()
    client = app.test_client()

    resp_ports = client.get("/api/ports")
    assert resp_ports.status_code == 200
    data = resp_ports.get_json()
    assert "ports" in data
    assert "total" in data
    assert data["total"] > 0

    resp_search = client.get("/api/ports/search?q=HTTP")
    assert resp_search.status_code == 200
    search_data = resp_search.get_json()
    assert search_data["count"] > 0

    resp_close = client.post("/api/ports/close", json={"port": 80, "protocol": "TCP"})
    assert resp_close.status_code == 200
    assert resp_close.get_json()["success"] is True

    resp_open = client.post("/api/ports/open", json={"port": 80, "protocol": "TCP"})
    assert resp_open.status_code == 200
    assert resp_open.get_json()["success"] is True


