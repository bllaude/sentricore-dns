import os
import tempfile
import json
from pathlib import Path

import pytest

from app.models.database import init_db, close_all_connections


@pytest.fixture(autouse=True)
def _api_key_setup(monkeypatch):
    """Tests exercise the legacy open-API behavior by default: no key is
    configured and writes are allowed.  Auth-specific tests set the key or
    toggle DENY_WRITES_WITHOUT_KEY explicitly via app.config/monkeypatch."""
    monkeypatch.delenv('SENTRICORE_API_KEY', raising=False)
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    import app.web.app as app_module
    monkeypatch.setattr(app_module, 'DENY_WRITES_WITHOUT_KEY', False)
    yield


@pytest.fixture(autouse=True)
def _clean_db_connections():
    yield
    close_all_connections()


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    for suffix in ('', '-wal', '-shm'):
        try:
            os.unlink(db_path + suffix)
        except OSError:
            pass


@pytest.fixture
def temp_config(temp_db):
    """Create a temporary config file for testing"""
    config = {
        "upstream_dns": ["1.1.1.1", 53],
        "listen_address": ["127.0.0.1", 0],
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
    import app.web.app as app_module

    monkeypatch.setattr(app_module, 'DB_PATH', temp_db)
    monkeypatch.setitem(app_module.CONFIG, 'database_path', temp_db)

    app_module.app.config['TESTING'] = True

    with app_module.app.test_client() as client:
        yield client
