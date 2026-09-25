import os
import sqlite3
import sys


sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from config.settings import DB_PATH


def get_connection():
    """Open a configured SQLite connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    connection = sqlite3.connect(
        DB_PATH,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


def get_column_names(connection, table_name):
    """Return the existing columns for a table."""
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {
        row["name"]
        for row in rows
    }


def add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition,
):
    """Apply an idempotent SQLite ADD COLUMN migration."""
    existing_columns = get_column_names(
        connection,
        table_name,
    )

    if column_name in existing_columns:
        return False

    connection.execute(
        f"""
        ALTER TABLE {table_name}
        ADD COLUMN {column_name} {column_definition}
        """
    )

    print(
        f"Added column: {table_name}.{column_name}"
    )

    return True


def migrate_predictions_table(connection):
    """Add live-classifier context to older databases."""
    migrations = [
        ("source_ip", "TEXT"),
        ("window_start", "TEXT"),
        ("window_end", "TEXT"),
        ("first_event_id", "INTEGER"),
        ("last_event_id", "INTEGER"),
        ("event_count", "INTEGER"),
        ("features_json", "TEXT"),
    ]

    for column_name, column_definition in migrations:
        add_column_if_missing(
            connection=connection,
            table_name="predictions",
            column_name=column_name,
            column_definition=column_definition,
        )

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_predictions_event_group
        ON predictions(event_group_id)
        WHERE event_group_id IS NOT NULL
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_predictions_source_last_event
        ON predictions(source_ip, last_event_id)
        """
    )


def create_indexes(connection):
    """Create indexes used by detection and live classification."""
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_source_event
        ON events(source_ip, event_id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_source_timestamp
        ON events(source_ip, timestamp)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_attackers_source
        ON attackers(source_ip)
        """
    )


def init_db():
    """Create the schema and safely migrate older databases."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
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
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS attackers (
            attacker_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT UNIQUE NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            risk_score INTEGER DEFAULT 0,
            primary_attack_type TEXT,
            status TEXT DEFAULT 'active'
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS decoys (
            decoy_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            type TEXT,
            container_name TEXT,
            status TEXT,
            activated_at TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS attacker_decoy_interactions (
            interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_id INTEGER,
            decoy_id INTEGER,
            first_interaction TEXT,
            last_interaction TEXT,
            interaction_count INTEGER DEFAULT 0,
            FOREIGN KEY (attacker_id)
                REFERENCES attackers(attacker_id),
            FOREIGN KEY (decoy_id)
                REFERENCES decoys(decoy_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS predictions (
            prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_group_id TEXT,
            predicted_class TEXT,
            confidence REAL,
            model_version TEXT,
            created_at TEXT,
            source_ip TEXT,
            window_start TEXT,
            window_end TEXT,
            first_event_id INTEGER,
            last_event_id INTEGER,
            event_count INTEGER,
            features_json TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS deception_decisions (
            decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER NOT NULL UNIQUE,
            source_ip TEXT NOT NULL,
            attack_class TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_bucket TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            decoy_key TEXT,
            reason TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            execution_mode TEXT NOT NULL DEFAULT 'observe',
            execution_status TEXT NOT NULL DEFAULT 'recommended',
            created_at TEXT NOT NULL,
            FOREIGN KEY (prediction_id)
                REFERENCES predictions(prediction_id)
        )
        """
    )

    migrate_predictions_table(connection)
    create_indexes(connection)

    connection.commit()
    connection.close()

    print("Database initialized at:", DB_PATH)


if __name__ == "__main__":
    init_db()
