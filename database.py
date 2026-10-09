import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "soc_lab.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_id TEXT NOT NULL,
            username TEXT DEFAULT '',
            source_ip TEXT DEFAULT '',
            message TEXT NOT NULL,
            source TEXT DEFAULT 'sample',
            UNIQUE(timestamp, event_id, username, source_ip, message)
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id_ref INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(event_id_ref) REFERENCES events(id) ON DELETE CASCADE,
            UNIQUE(event_id_ref, rule_name)
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        """)

def set_alert_status(alert_id, status):
    with get_connection() as conn:
        conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
