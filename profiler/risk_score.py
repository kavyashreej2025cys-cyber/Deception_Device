"""
Risk scoring logic. Converts detection findings + event volume
into a 0-100 numeric score and a severity bucket.
"""

SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 30,
    "CRITICAL": 40,
}

ATTACK_TYPE_WEIGHTS = {
    "RECONNAISSANCE": 10,
    "BRUTE_FORCE": 25,
    "DATABASE_PROBING": 20,
    "IOT_PROBING": 15,
    "MULTI_SERVICE_PROBE": 20,
    "WEB_ATTACK": 20,
}


def compute_risk_score(findings, event_count):
    """
    findings: list of finding dicts from rules.evaluate_source()
    event_count: total number of events from this source
    Returns: (score:int 0-100, bucket:str)
    """
    score = 0

    for f in findings:
        score += SEVERITY_WEIGHTS.get(f["severity"], 10)
        score += ATTACK_TYPE_WEIGHTS.get(f["attack_type"], 5)

    # Small bonus for sheer persistence/volume of activity
    if event_count >= 20:
        score += 15
    elif event_count >= 10:
        score += 8
    elif event_count >= 5:
        score += 3

    score = min(score, 100)

    if score <= 30:
        bucket = "LOW"
    elif score <= 60:
        bucket = "MEDIUM"
    elif score <= 80:
        bucket = "HIGH"
    else:
        bucket = "CRITICAL"

    return score, bucket
