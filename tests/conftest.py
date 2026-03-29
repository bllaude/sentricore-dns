import pytest
import tempfile
import json
import os
from pathlib import Path
from app.models.database import init_db
from app.web.app import app as flask_app


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    os.unlink(db_path)


@pytest.fixture
def temp_config(temp_db):
    """Create a temporary config file for testing"""
    config = {
        "upstream_dns": ["1.1.1.1", 53],
        "listen_address": ["0.0.0.0", 5300],
        "blocklist_path": "blocklists/malware.txt",
        "blocklist_sources": ["blocklists/malware.txt"],
        "blocklist_update_interval": 300,
        "cache_ttl": 300,
        "cache_max_size": 10000,
        "database_path": temp_db
    }
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(config, f)
        config_path = f.name
    yield config_path
    os.unlink(config_path)


@pytest.fixture
def flask_client(monkeypatch, temp_db):
    """Create a Flask test client with temp database"""
    # Mock the config to use temp database
    mock_config = {
        'database_path': temp_db
    }
    
    # Patch the CONFIG in the Flask app module
    import app.web.app as app_module
    original_db_path = app_module.DB_PATH
    app_module.DB_PATH = temp_db
    
    flask_app.config['TESTING'] = True
    
    with flask_app.test_client() as client:
        yield client
    
    # Restore original
    app_module.DB_PATH = original_db_path
