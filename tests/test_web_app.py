import pytest
import json
from app.models.database import log_query, inc_metric


def test_healthz_endpoint(flask_client):
    """Test /healthz returns ok status"""
    response = flask_client.get('/healthz')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'ok'
    assert 'time' in data


def test_dashboard_route(flask_client, temp_db):
    """Test dashboard route loads without error"""
    # Add some test data
    log_query('192.168.1.1', 'example.com', False, temp_db)
    log_query('192.168.1.2', 'bad.com', True, temp_db)
    inc_metric('total_queries', 2, temp_db)
    inc_metric('cache_hits', 1, temp_db)
    
    response = flask_client.get('/')
    
    assert response.status_code == 200
    assert b'Sentricore DNS Proxy Dashboard' in response.data
    assert b'Total Queries' in response.data
    assert b'Cache Hits' in response.data


def test_queries_route(flask_client, temp_db):
    """Test /queries route pagination"""
    # Add some test queries
    for i in range(5):
        log_query(f'192.168.1.{i}', f'domain{i}.com', False, temp_db)
    
    response = flask_client.get('/queries?page=1')
    
    assert response.status_code == 200
    assert b'All DNS Queries' in response.data


def test_queries_pagination(flask_client, temp_db):
    """Test queries pagination works"""
    # Add 105 queries
    for i in range(105):
        log_query(f'192.168.1.{i % 255}', f'domain{i}.com', False, temp_db)
    
    response = flask_client.get('/queries?page=1')
    assert response.status_code == 200
    
    response = flask_client.get('/queries?page=2')
    assert response.status_code == 200


def test_dashboard_calculates_cache_hit_rate(flask_client, temp_db):
    """Test dashboard calculates cache hit rate correctly"""
    inc_metric('cache_hits', 75, temp_db)
    inc_metric('cache_misses', 25, temp_db)
    inc_metric('total_queries', 100, temp_db)
    
    response = flask_client.get('/')
    assert response.status_code == 200
    assert b'75' in response.data  # cache_hits
    assert b'25' in response.data  # cache_misses
