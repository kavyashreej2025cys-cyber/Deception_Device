import json
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config.settings import HONEYPOT_SOURCES
from logger.database import get_connection, init_db

CURSOR_DIR = os.path.join(os.path.dirname(__file__), "cursors")
os.makedirs(CURSOR_DIR, exist_ok=True)


def get_cursor_path(cursor_key):
    return os.path.join(CURSOR_DIR, f"{cursor_key}.cursor")


def read_cursor(cursor_key):
    path = get_cursor_path(cursor_key)
    if os.path.exists(path):
        with open(path, "r") as f:
            return int(f.read().strip() or 0)
    return 0


def write_cursor(cursor_key, position):
    with open(get_cursor_path(cursor_key), "w") as f:
        f.write(str(position))


def normalize_cowrie(raw):
    event_type = raw.get("eventid", "unknown")
    return {
        "timestamp": raw.get("timestamp", ""),
        "source_ip": raw.get("src_ip", ""),
        "destination_ip": raw.get("dst_ip", ""),
        "event_type": event_type,
        "protocol": "ssh",
        "details": json.dumps(raw),
    }


def normalize_custom(raw):
    return {
        "timestamp": raw.get("timestamp", ""),
        "source_ip": raw.get("source_ip", ""),
        "destination_ip": "",
        "event_type": raw.get("event_type", "unknown"),
        "protocol": "http",
        "details": json.dumps(raw.get("details", {})),
    }


def process_source(source, conn):
    log_path = source["log_path"]
    service = source["service"]
    fmt = source["format"]
    cursor_key = source.get("cursor_key", service)

    if not os.path.exists(log_path):
        return 0

    cursor = read_cursor(cursor_key)
    new_events = 0

    with open(log_path, "r") as f:
        f.seek(cursor)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            if fmt == "cowrie":
                norm = normalize_cowrie(raw)
            else:
                norm = normalize_custom(raw)

            source_decoy_key = source.get("decoy_key")
            if source_decoy_key:
                details = json.loads(norm["details"] or "{}")
                if not isinstance(details, dict):
                    details = {"raw": details}
                details["decoy_key"] = source_decoy_key
                norm["details"] = json.dumps(details)

            conn.execute(
                "INSERT INTO events (timestamp, source_ip, destination_ip, service, event_type, protocol, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    norm["timestamp"],
                    norm["source_ip"],
                    norm["destination_ip"],
                    service,
                    norm["event_type"],
                    norm["protocol"],
                    norm["details"],
                ),
            )
            new_events += 1

        new_cursor = f.tell()

    write_cursor(cursor_key, new_cursor)
    return new_events


def run_once():
    conn = get_connection()
    total = 0
    for source in HONEYPOT_SOURCES:
        count = process_source(source, conn)
        if count:
            print(source.get("cursor_key", source["service"]), "ingested", count, "new event(s)")
        total += count
    conn.commit()
    conn.close()
    return total


def run_forever(interval=5):
    print("Central Logger started. Polling every", interval, "seconds. Ctrl+C to stop.")
    while True:
        run_once()
        time.sleep(interval)


if __name__ == "__main__":
    init_db()
    run_forever()
