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

    conn.commit()
    conn.close()


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
