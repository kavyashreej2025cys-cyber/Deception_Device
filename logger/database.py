import sqlite3
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config.settings import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        service TEXT NOT NULL,
        event_type TEXT NOT NULL,
        protocol TEXT,
        details TEXT,
        risk_score INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS attackers (
        attacker_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT UNIQUE NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        risk_score INTEGER DEFAULT 0,
        primary_attack_type TEXT,
        status TEXT DEFAULT 'active'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS decoys (
        decoy_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT,
        container_name TEXT,
        status TEXT,
        activated_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS attacker_decoy_interactions (
        interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_id INTEGER,
        decoy_id INTEGER,
        first_interaction TEXT,
        last_interaction TEXT,
        interaction_count INTEGER DEFAULT 0,
        FOREIGN KEY (attacker_id) REFERENCES attackers(attacker_id),
        FOREIGN KEY (decoy_id) REFERENCES decoys(decoy_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS predictions (
        prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_group_id TEXT,
        predicted_class TEXT,
        confidence REAL,
        model_version TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()
    print("Database initialized at:", DB_PATH)

if __name__ == "__main__":
    init_db()
