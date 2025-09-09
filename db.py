import sqlite3
from pathlib import Path

DB_PATH = Path("ir.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule_level INTEGER,
            rule_description TEXT,
            srcip TEXT,
            agent_name TEXT,
            status TEXT DEFAULT 'open',
            intel_score INTEGER,
            intel_country TEXT,
            intel_reports INTEGER,
            summary TEXT
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            action TEXT,
            status TEXT,       -- queued, approved, executed, failed
            output TEXT,
            FOREIGN KEY(alert_id) REFERENCES alerts(id)
        )
        """)
        conn.commit()

def insert_alert(a):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO alerts(timestamp, rule_level, rule_description, srcip, agent_name, status, intel_score, intel_country, intel_reports, summary)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
        """, (a["timestamp"], a["rule_level"], a["rule_description"], a.get("srcip"),
              a.get("agent_name"), a.get("intel_score"), a.get("intel_country"),
              a.get("intel_reports"), a.get("summary")))
        conn.commit()
        return c.lastrowid

def list_alerts():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM alerts ORDER BY id DESC")]

def get_alert(alert_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else None

def update_status(alert_id, status):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        conn.commit()

def queue_action(alert_id, action):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO actions(alert_id, action, status, output) VALUES (?, ?, 'queued', '')",
                  (alert_id, action))
        conn.commit()
        return c.lastrowid

def list_actions(alert_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM actions WHERE alert_id=?", (alert_id,))]
