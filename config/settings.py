"""
Central configuration for the Cyber Deception System.
Import from here instead of hardcoding values across modules.
"""

# IP prefixes to ignore across the entire pipeline —
# these are Docker-internal/bridge addresses, not real external sources.
IGNORE_IP_PREFIXES = (
    "172.",     # Docker default bridge range
    "127.",     # loopback
    "10.0.",    # sometimes used by Docker/Compose networks
)

# Central database path
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "events.db")

# Honeypot log source definitions — single source of truth
HONEYPOT_SOURCES = [
    {
        "service": "ssh",
        "log_path": os.path.join(BASE_DIR, "honeypots", "ssh", "logs", "cowrie.json"),
        "format": "cowrie",
    },
    {
        "service": "web",
        "log_path": os.path.join(BASE_DIR, "honeypots", "web", "logs", "web_events.json"),
        "format": "custom",
    },
    {
        "service": "database",
        "log_path": os.path.join(BASE_DIR, "honeypots", "database", "logs", "db_events.json"),
        "format": "custom",
    },
    {
        "service": "iot",
        "log_path": os.path.join(BASE_DIR, "honeypots", "iot", "logs", "iot_events.json"),
        "format": "custom",
    },
    {
        "service": "database",
        "cursor_key": "finance_database",
        "log_path": os.path.join(
            BASE_DIR,
            "adaptive",
            "decoys",
            "finance_database",
            "logs",
            "finance_events.json",
        ),
        "format": "custom",
    },
    {
        "service": "iot",
        "cursor_key": "camera_management",
        "log_path": os.path.join(
            BASE_DIR,
            "adaptive",
            "decoys",
            "camera_management",
            "logs",
            "camera_events.json",
        ),
        "format": "custom",
    },
]
