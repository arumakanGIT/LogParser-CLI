import sqlite3
from pathlib import Path

DB_DIR = Path.home() / ".log_analyzer_app"
DB_FILE = DB_DIR / "settings.db"

def init_db():
    DB_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_setting(key, default_value):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return default_value
    return row[0]

def set_setting(key, value):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO settings (key, value) 
        VALUES (?, ?)
    """, (key, str(value)))
    conn.commit()
    conn.close()

def load_app_settings():
    init_db()
    path_val = get_setting("path", "access.log")
    live_log_val = get_setting("live_log", "False") == "True"
    return path_val, live_log_val

def save_app_settings(path_val, live_log_val):
    set_setting("path", path_val)
    set_setting("live_log", live_log_val)
