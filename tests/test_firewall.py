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
