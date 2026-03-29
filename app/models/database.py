import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"


def init_db(db_path=None):
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    else:
        db_path = Path(db_path)
        db_path.parent.mkdir(exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            domain TEXT,
            blocked INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            key TEXT PRIMARY KEY,
            value INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            source TEXT DEFAULT 'api',
            added_at TEXT
        )
    """)

    # Initialize metrics keys
    for metric in ('cache_hits', 'cache_misses', 'total_queries'):
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES (?, 0)", (metric,))

    conn.commit()
    conn.close()


def inc_metric(key, amount=1, db_path=None):
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE metrics SET value = value + ? WHERE key = ?", (amount, key))
    conn.commit()
    conn.close()


def get_metrics(db_path=None):
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM metrics")
    rows = cursor.fetchall()
    conn.close()
    return {k: v for k, v in rows}


def add_blocklist_domain(domain, db_path=None):
    """Add a domain to the blocklist"""
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO blocklist (domain, source, added_at) VALUES (?, 'api', ?)",
            (domain.lower(), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def remove_blocklist_domain(domain, db_path=None):
    """Remove a domain from the blocklist"""
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocklist WHERE domain = ?", (domain.lower(),))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return deleted > 0


def get_blocklist_domains(db_path=None):
    """Get all domains in the blocklist"""
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, source, added_at FROM blocklist ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{'domain': row[0], 'source': row[1], 'added_at': row[2]} for row in rows]


def log_query(client_ip, domain, blocked, db_path=None):
    if db_path is None:
        db_path = DATA_DIR / "sentricore.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO queries (timestamp, client_ip, domain, blocked)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        client_ip,
        domain,
        int(blocked)
    ))

    conn.commit()
    conn.close()
