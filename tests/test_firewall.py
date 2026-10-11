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
