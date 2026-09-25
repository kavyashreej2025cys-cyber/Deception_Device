"""
Rule-based detection logic.
Each rule takes a list of event rows (dicts) for a single source_ip
and returns a finding dict if the pattern matches, or None.
"""

def rule_reconnaissance(events):
    """Many distinct services/paths touched rapidly = recon."""
    services = set(e["service"] for e in events)
    if len(services) >= 2 and len(events) >= 5:
        return {
            "attack_type": "RECONNAISSANCE",
            "reason": f"Source touched {len(services)} services with {len(events)} events",
            "severity": "MEDIUM",
        }
    return None


def rule_brute_force(events):
    """Repeated login attempts on ssh or web/db/iot = brute force."""
    login_events = [
        e for e in events
        if e["event_type"] in ("login_attempt", "cowrie.login.failed", "cowrie.login.success")
    ]
    if len(login_events) >= 3:
        return {
            "attack_type": "BRUTE_FORCE",
            "reason": f"{len(login_events)} login attempts detected",
            "severity": "HIGH",
        }
    return None


def rule_multi_service_probe(events):
    """Same source touching 3+ different decoy services = elevated risk."""
    services = set(e["service"] for e in events)
    if len(services) >= 3:
        return {
            "attack_type": "MULTI_SERVICE_PROBE",
            "reason": f"Source interacted with {len(services)} distinct services: {', '.join(services)}",
            "severity": "HIGH",
        }
    return None


def rule_database_probing(events):
    """Query attempts or table access on the DB honeypot."""
    db_events = [
        e for e in events
        if e["service"] == "database" and e["event_type"] in ("query_attempt", "table_access")
    ]
    if len(db_events) >= 2:
        return {
            "attack_type": "DATABASE_PROBING",
            "reason": f"{len(db_events)} database probing events",
            "severity": "HIGH",
        }
    return None


def rule_iot_probing(events):
    """Camera view attempts or config access on the IoT honeypot."""
    iot_events = [
        e for e in events
        if e["service"] == "iot" and e["event_type"] in ("view_camera_attempt", "config_access_attempt")
    ]
    if len(iot_events) >= 2:
        return {
            "attack_type": "IOT_PROBING",
            "reason": f"{len(iot_events)} IoT probing events",
            "severity": "MEDIUM",
        }
    return None


# Order matters a little here — more specific/severe rules can be checked first
ALL_RULES = [
    rule_brute_force,
    rule_database_probing,
    rule_iot_probing,
    rule_multi_service_probe,
    rule_reconnaissance,
]


def evaluate_source(events):
    """
    Run all rules against a source's event list.
    Returns a list of all matching findings (a source can match multiple rules).
    """
    findings = []
    for rule in ALL_RULES:
        result = rule(events)
        if result:
            findings.append(result)
    return findings
