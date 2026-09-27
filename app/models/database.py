import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"

# Per-process cache of open SQLite connections keyed by resolved db path.
_connections = {}
_lock = threading.Lock()

DEFAULT_RETENTION_DAYS = 30


def _resolve_db_path(db_path=None):
    if db_path is None:
        return str(DATA_DIR / "sentricore.db")
    path = Path(db_path)
    if not path.is_absolute():
        path = BASE_DIR / path
    return str(path)


def get_connection(db_path=None):
    """Return a persistent connection for ``db_path`` (created on first use).

    Opening one connection per query was the main hot-path bottleneck; reusing
    a WAL-mode connection removes that cost entirely.
    """
    resolved = _resolve_db_path(db_path)
    with _lock:
        conn = _connections.get(resolved)
        if conn is None:
            Path(resolved).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(resolved, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            _connections[resolved] = conn
        return conn


def close_all_connections():
    with _lock:
        for conn in _connections.values():
            try:
                conn.close()
            except Exception:
                pass
        _connections.clear()


def init_db(db_path=None):
    conn = get_connection(db_path)
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

    # Indexes for the dashboard's hottest queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp)")

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


def inc_metric(key, amount=1, db_path=None):
    conn = get_connection(db_path)
    conn.execute(
        "INSERT INTO metrics (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
        (key, amount),
    )
    conn.commit()


def inc_metrics_batch(deltas, db_path=None):
    """Apply several metric increments in a single transaction."""
    if not deltas:
        return
    conn = get_connection(db_path)
    with conn:
        conn.executemany(
            "INSERT INTO metrics (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            list(deltas.items()),
        )


def get_metrics(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM metrics")
    rows = cursor.fetchall()
    return {k: v for k, v in rows}


def add_blocklist_domain(domain, db_path=None):
    """Add a domain to the blocklist"""
    conn = get_connection(db_path)
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


def remove_blocklist_domain(domain, db_path=None):
    """Remove a domain from the blocklist"""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocklist WHERE domain = ?", (domain.lower(),))
    conn.commit()
    return cursor.rowcount > 0


def get_blocklist_domains(db_path=None):
    """Get all domains in the blocklist"""
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT domain, source, added_at FROM blocklist ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.row_factory = None
    return [{'domain': row['domain'], 'source': row['source'], 'added_at': row['added_at']} for row in rows]


def log_query(client_ip, domain, blocked, db_path=None):
    conn = get_connection(db_path)
    conn.execute(
        "INSERT INTO queries (timestamp, client_ip, domain, blocked) VALUES (?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), client_ip, domain, int(blocked)),
    )
    conn.commit()


def log_queries_batch(rows, db_path=None):
    """Insert many (timestamp, client_ip, domain, blocked) tuples in one txn."""
    if not rows:
        return
    conn = get_connection(db_path)
    with conn:
        conn.executemany(
            "INSERT INTO queries (timestamp, client_ip, domain, blocked) VALUES (?, ?, ?, ?)",
            rows,
        )


def prune_old_queries(db_path=None, retention_days=DEFAULT_RETENTION_DAYS):
    """Delete query rows older than ``retention_days`` to bound DB growth."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    conn = get_connection(db_path)
    with conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM queries WHERE timestamp < ?", (cutoff,))
        return cursor.rowcount
