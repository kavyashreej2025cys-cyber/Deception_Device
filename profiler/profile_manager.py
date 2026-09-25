import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "logger"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detection"))

from config.settings import IGNORE_IP_PREFIXES
from database import get_connection
from rules import evaluate_source
from risk_score import compute_risk_score


def fetch_events_by_source():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE source_ip IS NOT NULL AND source_ip != ''")
    rows = cur.fetchall()
    conn.close()

    grouped = {}
    for row in rows:
        event = dict(row)
        ip = event["source_ip"]
        if ip.startswith(IGNORE_IP_PREFIXES):
            continue
        grouped.setdefault(ip, []).append(event)
    return grouped


def upsert_attacker(conn, ip, events, findings, score, bucket):
    timestamps = sorted(e["timestamp"] for e in events if e["timestamp"])
    first_seen = timestamps[0] if timestamps else None
    last_seen = timestamps[-1] if timestamps else None

    primary_attack_type = findings[0]["attack_type"] if findings else "NORMAL"

    cur = conn.cursor()
    cur.execute("SELECT attacker_id FROM attackers WHERE source_ip = ?", (ip,))
    existing = cur.fetchone()

    if existing:
        cur.execute(
            "UPDATE attackers SET last_seen = ?, risk_score = ?, primary_attack_type = ?, status = 'active' WHERE source_ip = ?",
            (last_seen, score, primary_attack_type, ip),
        )
    else:
        cur.execute(
            "INSERT INTO attackers (source_ip, first_seen, last_seen, risk_score, primary_attack_type, status) VALUES (?, ?, ?, ?, ?, 'active')",
            (ip, first_seen, last_seen, score, primary_attack_type),
        )


def run_profiling():
    grouped = fetch_events_by_source()
    conn = get_connection()

    for ip, events in grouped.items():
        findings = evaluate_source(events)
        score, bucket = compute_risk_score(findings, len(events))
        upsert_attacker(conn, ip, events, findings, score, bucket)

        print(f"\n=== Attacker Profile: {ip} ===")
        print(f"  Events: {len(events)}")
        print(f"  Risk Score: {score}/100 ({bucket})")
        if findings:
            print(f"  Primary Attack: {findings[0]['attack_type']}")
            for f in findings:
                print(f"    - {f['attack_type']}: {f['reason']}")
        else:
            print("  No suspicious pattern detected.")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    run_profiling()
