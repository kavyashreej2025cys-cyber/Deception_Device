"""Synchronize lab-only nftables redirects with active adaptive decoys.

Only new TCP connections from explicitly allowed lab source networks are
redirected. Existing connections remain pinned by Linux conntrack. The
service owns only the ``inet deception_redirect`` table and never modifies
other firewall tables.
"""

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


TABLE_FAMILY = "inet"
TABLE_NAME = "deception_redirect"
CHAIN_NAME = "prerouting"
# Docker installs destination-NAT rules at priority -100. Run slightly
# earlier so an approved deception redirect sees the original service port.
CHAIN_PRIORITY = -110
DEFAULT_POLL_SECONDS = 2

ALLOWED_NETWORK = ipaddress.ip_network(
    os.getenv("DECEPTION_REDIRECT_ALLOWED_NETWORK", "192.168.56.0/24")
)

# The attacker continues to use the original service port. Only the backend
# destination changes after the matching adaptive decoy becomes active.
DECOY_REDIRECTS = {
    "ssh_admin_server": ((2222, 2224),),
    "service_discovery": ((5000, 15000),),
    "finance_database": ((5432, 15432),),
    "camera_management": ((8080, 18080),),
    "layered_enterprise": (
        (2222, 2226),
        (5000, 16000),
        (5432, 16432),
    ),
}


def valid_source_ip(value):
    """Return a normalized source IP restricted to the isolated lab."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if address.version != 4 or address not in ALLOWED_NETWORK:
        return None

    return str(address)


def activation_source(details, decision_source):
    """Extract the approved attacker source from lifecycle evidence."""
    if decision_source:
        return valid_source_ip(decision_source)

    try:
        parsed = json.loads(details or "{}")
    except (TypeError, json.JSONDecodeError):
        return None

    return valid_source_ip(parsed.get("source_ip", ""))


def fetch_desired_routes():
    """Return redirects for active decoys with attributable activations."""
    connection = get_connection()

    try:
        active_decoys = connection.execute(
            """
            SELECT name
            FROM decoys
            WHERE status = 'active'
            ORDER BY decoy_id
            """
        ).fetchall()

        routes = []

        for decoy in active_decoys:
            decoy_key = decoy["name"]
            port_pairs = DECOY_REDIRECTS.get(decoy_key)
            if not port_pairs:
                continue

            event = connection.execute(
                """
                SELECT l.details, d.source_ip AS decision_source
                FROM decoy_lifecycle_events AS l
                LEFT JOIN deception_decisions AS d
                  ON d.decision_id = l.decision_id
                WHERE l.decoy_key = ?
                  AND l.action = 'ACTIVATE'
                  AND l.status IN ('completed', 'already_active')
                ORDER BY l.lifecycle_event_id DESC
                LIMIT 1
                """,
                (decoy_key,),
            ).fetchone()

            if event is None:
                continue

            source_ip = activation_source(
                event["details"],
                event["decision_source"],
            )
            if source_ip is None:
                continue

            for original_port, decoy_port in port_pairs:
                routes.append(
                    {
                        "source_ip": source_ip,
                        "decoy_key": decoy_key,
                        "original_port": original_port,
                        "decoy_port": decoy_port,
                    }
                )
    finally:
        connection.close()

    # Remove duplicates while preserving deterministic ordering.
    unique = {}
    for route in routes:
        key = (route["source_ip"], route["original_port"])
        unique[key] = route

    return [unique[key] for key in sorted(unique)]


def run_nft(arguments, input_text=None, check=True):
    """Execute nft without a shell or attacker-controlled arguments."""
    return subprocess.run(
        ["/usr/sbin/nft", *arguments],
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


def ensure_owned_table():
    """Create the dedicated table and NAT chain when absent."""
    result = run_nft(
        ["list", "table", TABLE_FAMILY, TABLE_NAME],
        check=False,
    )
    if result.returncode == 0:
        return

    ruleset = f"""
add table {TABLE_FAMILY} {TABLE_NAME}
add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type nat hook prerouting priority {CHAIN_PRIORITY}; policy accept; }}
"""
    run_nft(["-f", "-"], input_text=ruleset)


def build_ruleset(routes):
    """Build an nft script using only validated values and fixed ports."""
    lines = [
        f"flush chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME}"
    ]

    for route in routes:
        lines.append(
            "add rule "
            f"{TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} "
            f"ip saddr {route['source_ip']} "
            f"tcp dport {route['original_port']} "
            f"ct state new counter redirect to :{route['decoy_port']} "
            f"comment \"decoy:{route['decoy_key']}\""
        )

    return "\n".join(lines) + "\n"


def apply_routes(routes):
    """Atomically replace rules in the service-owned chain."""
    ensure_owned_table()
    run_nft(["-f", "-"], input_text=build_ruleset(routes))


def run_once(dry_run=False):
    """Calculate and optionally apply the current redirect state."""
    routes = fetch_desired_routes()
    if not dry_run:
        apply_routes(routes)
    return routes


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Synchronize guarded adaptive-decoy redirects."
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=DEFAULT_POLL_SECONDS,
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    if args.poll_seconds <= 0:
        raise SystemExit("--poll-seconds must be greater than zero")

    previous = None
    while True:
        try:
            routes = run_once(dry_run=args.dry_run)
            serialized = json.dumps(routes, sort_keys=True)
            if serialized != previous:
                print(serialized, flush=True)
                previous = serialized
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            print(f"Redirect synchronization failed: {error}", file=sys.stderr, flush=True)

        if args.once:
            break
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
