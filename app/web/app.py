from flask import Flask, render_template, request
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "sentricore.db"

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

    # Recent queries
    cursor.execute("SELECT * FROM queries ORDER BY timestamp DESC LIMIT 50")
    recent_queries = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html', 
                         total_queries=total_queries, 
                         blocked_queries=blocked_queries, 
                         top_blocked=top_blocked,
                         recent_queries=recent_queries)

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