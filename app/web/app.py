from flask import Flask, render_template, request, jsonify
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from app.models.database import add_blocklist_domain, remove_blocklist_domain, get_blocklist_domains

app = Flask(__name__)

CONFIG = json.load(open('config.json'))
DB_PATH = CONFIG['database_path']

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total queries
    cursor.execute("SELECT COUNT(*) as total FROM queries")
    total_queries = cursor.fetchone()['total']

    # Blocked queries
    cursor.execute("SELECT COUNT(*) as blocked FROM queries WHERE blocked = 1")
    blocked_queries = cursor.fetchone()['blocked']

    # Top blocked domains
    cursor.execute("""
        SELECT domain, COUNT(*) as count 
        FROM queries 
        WHERE blocked = 1 
        GROUP BY domain 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_blocked = cursor.fetchall()

    # Metrics
    cursor.execute("SELECT key, value FROM metrics")
    metrics_rows = cursor.fetchall()
    metrics = {row['key']: row['value'] for row in metrics_rows}

    cache_hits = metrics.get('cache_hits', 0)
    cache_misses = metrics.get('cache_misses', 0)
    cache_total = cache_hits + cache_misses
    cache_hit_rate = (cache_hits / cache_total * 100) if cache_total > 0 else 0

    # Recent queries
    cursor.execute("SELECT * FROM queries ORDER BY timestamp DESC LIMIT 50")
    recent_queries = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html', 
                         total_queries=total_queries, 
                         blocked_queries=blocked_queries, 
                         top_blocked=top_blocked,
                         recent_queries=recent_queries,
                         cache_hits=cache_hits,
                         cache_misses=cache_misses,
                         cache_hit_rate=cache_hit_rate)

@app.route('/healthz')
def healthz():
    return {
        'status': 'ok',
        'time': datetime.now(timezone.utc).isoformat()
    }, 200


@app.route('/queries')
def queries():
    page = request.args.get('page', 1, type=int)
    per_page = 100
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM queries")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT * FROM queries ORDER BY timestamp DESC LIMIT ? OFFSET ?", (per_page, offset))
    queries_list = cursor.fetchall()

    conn.close()

    return render_template('queries.html', queries=queries_list, page=page, total=total, per_page=per_page)

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """Get all blocked domains from the database"""
    domains = get_blocklist_domains(DB_PATH)
    return jsonify({'domains': domains, 'count': len(domains)}), 200


@app.route('/api/blocklist', methods=['POST'])
def add_blocklist():
    """Add a domain to the blocklist"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'domain field required'}), 400
    
    domain = data['domain'].lower().strip()
    if not domain:
        return jsonify({'error': 'domain cannot be empty'}), 400
    
    success = add_blocklist_domain(domain, DB_PATH)
    if success:
        return jsonify({'message': f'Domain {domain} added to blocklist'}), 201
    else:
        return jsonify({'error': f'Domain {domain} already in blocklist'}), 409


@app.route('/api/blocklist/<domain>', methods=['DELETE'])
def remove_blocklist(domain):
    """Remove a domain from the blocklist"""
    domain = domain.lower().strip()
    success = remove_blocklist_domain(domain, DB_PATH)
    
    if success:
        return jsonify({'message': f'Domain {domain} removed from blocklist'}), 200
    else:
        return jsonify({'error': f'Domain {domain} not found in blocklist'}), 404
