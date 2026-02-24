import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "sentricore.db"


def init_db():
    DATA_DIR.mkdir(exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
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


def log_query(client_ip, domain, blocked):
    conn = sqlite3.connect(DB_PATH)
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
