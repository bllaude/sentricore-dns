import pytest
import sqlite3
from app.models.database import init_db, log_query, inc_metric, get_metrics


def test_init_db_creates_tables(temp_db):
    """Test that init_db creates required tables"""
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    
    assert 'queries' in tables
    assert 'metrics' in tables
    conn.close()


def test_init_db_creates_metrics(temp_db):
    """Test that init_db initializes metrics"""
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM metrics")
    metrics = {row[0] for row in cursor.fetchall()}
    
    assert 'cache_hits' in metrics
    assert 'cache_misses' in metrics
    assert 'total_queries' in metrics
    conn.close()


def test_log_query(temp_db):
    """Test logging a query to database"""
    log_query('192.168.1.1', 'example.com', False, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT client_ip, domain, blocked FROM queries")
    rows = cursor.fetchall()
    
    assert len(rows) == 1
    assert rows[0][0] == '192.168.1.1'
    assert rows[0][1] == 'example.com'
    assert rows[0][2] == 0
    conn.close()


def test_log_blocked_query(temp_db):
    """Test logging a blocked query"""
    log_query('192.168.1.1', 'malware.com', True, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT blocked FROM queries WHERE domain='malware.com'")
    blocked = cursor.fetchone()[0]
    
    assert blocked == 1
    conn.close()


def test_inc_metric(temp_db):
    """Test incrementing a metric"""
    inc_metric('cache_hits', 5, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM metrics WHERE key='cache_hits'")
    value = cursor.fetchone()[0]
    
    assert value == 5
    conn.close()


def test_inc_metric_multiple_times(temp_db):
    """Test incrementing the same metric multiple times"""
    inc_metric('cache_misses', 1, temp_db)
    inc_metric('cache_misses', 1, temp_db)
    inc_metric('cache_misses', 1, temp_db)
    
    metrics = get_metrics(temp_db)
    assert metrics['cache_misses'] == 3


def test_get_metrics(temp_db):
    """Test retrieving all metrics"""
    inc_metric('cache_hits', 10, temp_db)
    inc_metric('total_queries', 25, temp_db)
    
    metrics = get_metrics(temp_db)
    
    assert metrics['cache_hits'] == 10
    assert metrics['total_queries'] == 25
    assert 'cache_misses' in metrics
