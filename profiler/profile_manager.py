import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "logger"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detection"))

from config.settings import IGNORE_IP_PREFIXES
from logger.database import get_connection
from detection.rules import evaluate_source
from profiler.risk_score import compute_risk_score


RISK_WINDOW_MINUTES = int(
    os.getenv("DECEPTION_RISK_WINDOW_MINUTES", "15")
)


def fetch_events_by_source():
    conn = get_connection()
    cur = conn.cursor()
    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(minutes=RISK_WINDOW_MINUTES)
    ).isoformat().replace("+00:00", "Z")
    cur.execute(
        """
        SELECT * FROM events
        WHERE source_ip IS NOT NULL
          AND source_ip != ''
          AND timestamp >= ?
        ORDER BY event_id
        """,
        (cutoff,),
    )
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
    cur.execute(
        "SELECT attacker_id, peak_risk_score FROM attackers WHERE source_ip = ?",
        (ip,),
    )
    existing = cur.fetchone()

    if existing:
        cur.execute(
            """
            UPDATE attackers
            SET last_seen = ?, risk_score = ?, peak_risk_score = ?,
                risk_bucket = ?, primary_attack_type = ?, status = 'active'
            WHERE source_ip = ?
            """,
            (
                last_seen,
                score,
                max(int(existing["peak_risk_score"] or 0), score),
                bucket,
                primary_attack_type,
                ip,
            ),
        )
    else:
        cur.execute(
            """
            INSERT INTO attackers (
                source_ip, first_seen, last_seen, risk_score,
                peak_risk_score, risk_bucket, primary_attack_type, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (ip, first_seen, last_seen, score, score, bucket, primary_attack_type),
        )


def run_profiling():
    grouped = fetch_events_by_source()
    conn = get_connection()

    active_sources = set(grouped)
    for row in conn.execute("SELECT source_ip FROM attackers"):
        if row["source_ip"] not in active_sources:
            conn.execute(
                """
                UPDATE attackers
                SET risk_score = 0, risk_bucket = 'LOW', status = 'inactive'
                WHERE source_ip = ?
                """,
                (row["source_ip"],),
            )

    for ip, events in grouped.items():
        findings = evaluate_source(events)
        unique_services = len({
            event.get("service")
            for event in events
            if event.get("service")
        })
        score, bucket = compute_risk_score(
            findings=findings,
            event_count=len(events),
            unique_services=unique_services,
            events=events,
            window_minutes=RISK_WINDOW_MINUTES,
        )
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
