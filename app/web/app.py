"""Sentricore DNS web dashboard.

route handlers are defined at import time (nothing lives under
``if __name__ == '__main__'``) so the module can be imported by gunicorn,
``flask --app``, or tests.  
paths resolve relative to the project root, and
the blocklist API is authenticated with a constant-time key comparison.
"""

import hmac
import json
import os
import re
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from app.models.database import (
    add_blocklist_domain,
    get_blocklist_domains,
    get_metrics,
    init_db,
    remove_blocklist_domain,
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent

app = Flask(__name__)

DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?)+$'
)


def _load_config():
    config_path = os.getenv('SENTRICORE_CONFIG') or str(BASE_DIR / 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


CONFIG = _load_config()


def _resolve_db_path():
    env = os.getenv('SENTRICORE_DB')
    raw = env or CONFIG.get('database_path', 'data/sentricore.db')
    path = Path(raw)
    if not path.is_absolute():
        path = BASE_DIR / path
    return str(path)


DB_PATH = _resolve_db_path()

# API key protecting the blocklist endpoints.  Resolution order:
# SENTRICORE_API_KEY -> DASHBOARD_API_KEY -> app.config['API_KEY'] (tests /
# programmatic config).  When a key is configured every /api/blocklist
# request must present it via the X-API-Key header (constant-time compare).
AUTH_API_KEY = os.getenv('SENTRICORE_API_KEY') or os.getenv('DASHBOARD_API_KEY')

# hardening switch: when true (default), POST/DELETE on the blocklist API are
# rejected with 403 unless a server-side API key is configured.  Set to false
# only for trusted single-user/local deployments that want the legacy open
# behavior.
DENY_WRITES_WITHOUT_KEY = os.getenv('SENTRICORE_DENY_WRITES_WITHOUT_KEY', '1') != '0'


def _configured_api_key():
    return (os.getenv('SENTRICORE_API_KEY') or
            os.getenv('DASHBOARD_API_KEY') or
            app.config.get('API_KEY'))


def _keys_match(a, b):
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def require_api_key(func):
    """enforce the configured key; when no key is configured fall back to
    the legacy open behavior for reads and deny-by-default for writes via
    ``DENY_WRITES_WITHOUT_KEY``."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        configured = _configured_api_key() or AUTH_API_KEY
        if not configured:
            if DENY_WRITES_WITHOUT_KEY and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                return jsonify({
                    'error': 'Server-side API key not configured; '
                             'set SENTRICORE_API_KEY to enable this endpoint'
                }), 403
            return func(*args, **kwargs)
        # header only - query-string keys leak into logs/referrers
        request_key = request.headers.get('X-API-Key')
        if not request_key or not _keys_match(request_key, configured):
            return jsonify({'error': 'Unauthorized'}), 401
        return func(*args, **kwargs)
    return wrapper


def get_db_connection():
    conn = sqlite3.connect(_resolve_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def _valid_domain(domain):
    return bool(domain) and bool(DOMAIN_RE.match(domain))


@app.route('/')
def dashboard():
    db_path = _resolve_db_path()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM queries")
    total_queries = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as blocked FROM queries WHERE blocked = 1")
    blocked_queries = cursor.fetchone()['blocked']

    cursor.execute("""
        SELECT domain, COUNT(*) as count
        FROM queries
        WHERE blocked = 1
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
    """)
    top_blocked = cursor.fetchall()

    metrics = get_metrics(db_path)

    cache_hits = metrics.get('cache_hits', 0)
    cache_misses = metrics.get('cache_misses', 0)
    cache_total = cache_hits + cache_misses
    cache_hit_rate = (cache_hits / cache_total * 100) if cache_total > 0 else 0

    cursor.execute("SELECT * FROM queries ORDER BY timestamp DESC LIMIT 50")
    recent_queries = cursor.fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        total_queries=total_queries,
        blocked_queries=blocked_queries,
        top_blocked=top_blocked,
        recent_queries=recent_queries,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        cache_hit_rate=cache_hit_rate,
    )


@app.route('/healthz')
def healthz():
    from datetime import datetime, timezone
    return {
        'status': 'ok',
        'time': datetime.now(timezone.utc).isoformat()
    }, 200


@app.route('/metrics')
def metrics():
    """expose metrics in prometheus text format."""
    db_path = _resolve_db_path()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM queries")
    total_queries = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as blocked FROM queries WHERE blocked = 1")
    blocked_queries = cursor.fetchone()['blocked']

    app_metrics = get_metrics(db_path)
    cache_hits = app_metrics.get('cache_hits', 0)
    cache_misses = app_metrics.get('cache_misses', 0)

    cursor.execute("SELECT COUNT(*) as count FROM blocklist")
    blocklist_size = cursor.fetchone()['count']

    conn.close()

    prometheus_output = """# HELP sentricore_total_queries Total DNS queries processed
# TYPE sentricore_total_queries counter
sentricore_total_queries {0}
# HELP sentricore_blocked_queries Total blocked queries
# TYPE sentricore_blocked_queries counter
sentricore_blocked_queries {1}
# HELP sentricore_cache_hits Total cache hits
# TYPE sentricore_cache_hits counter
sentricore_cache_hits {2}
# HELP sentricore_cache_misses Total cache misses
# TYPE sentricore_cache_misses counter
sentricore_cache_misses {3}
# HELP sentricore_blocklist_size Current blocklist domain count
# TYPE sentricore_blocklist_size gauge
sentricore_blocklist_size {4}
""".format(total_queries, blocked_queries, cache_hits, cache_misses, blocklist_size)

    return prometheus_output, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/queries')
def queries():
    page = max(request.args.get('page', 1, type=int) or 1, 1)
    per_page = min(max(request.args.get('per_page', 100, type=int) or 100, 1), 500)
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM queries")
    total = cursor.fetchone()['total']

    cursor.execute(
        "SELECT * FROM queries ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    )
    queries_list = cursor.fetchall()

    conn.close()

    return render_template('queries.html', queries=queries_list, page=page,
                           total=total, per_page=per_page)


@app.route('/api/blocklist', methods=['GET'])
@require_api_key
def get_blocklist():
    """get all blocked domains from the database."""
    domains = get_blocklist_domains(_resolve_db_path())
    return jsonify({'domains': domains, 'count': len(domains)}), 200


@app.route('/api/blocklist', methods=['POST'])
@require_api_key
def add_blocklist():
    """add a domain to the blocklist."""
    data = request.get_json(silent=True)
    if not data or 'domain' not in data:
        return jsonify({'error': 'domain field required'}), 400

    domain = str(data['domain']).lower().strip().rstrip('.')
    if not domain:
        return jsonify({'error': 'domain cannot be empty'}), 400
    if not _valid_domain(domain):
        return jsonify({'error': 'invalid domain name'}), 400

    success = add_blocklist_domain(domain, _resolve_db_path())
    if success:
        return jsonify({'message': f'Domain {domain} added to blocklist'}), 201
    else:
        return jsonify({'error': f'Domain {domain} already in blocklist'}), 409


@app.route('/api/blocklist/<path:domain>', methods=['DELETE'])
@require_api_key
def remove_blocklist(domain):
    """remove a domain from the blocklist."""
    domain = domain.lower().strip().rstrip('.')
    if not _valid_domain(domain):
        return jsonify({'error': 'invalid domain name'}), 400

    success = remove_blocklist_domain(domain, _resolve_db_path())
    if success:
        return jsonify({'message': f'Domain {domain} removed from blocklist'}), 200
    else:
        return jsonify({'error': f'Domain {domain} not found in blocklist'}), 404


def main():
    """local dev entry point, prod should use gunicorn."""
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    host = os.getenv('SENTRICORE_WEB_HOST', '127.0.0.1')
    port = int(os.getenv('SENTRICORE_WEB_PORT', '5000'))
    if host != '127.0.0.1' and debug:
        raise RuntimeError(
            'Refusing to run the Werkzeug debugger on a non-loopback address '
            '(remote code execution risk). Unset FLASK_DEBUG or use gunicorn.'
        )
    init_db(DB_PATH)
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()