"""Threat classifier — categorizes detected issues by MITRE ATT&CK-style labels."""


THREAT_CATEGORIES = {
    "brute_force": "Credential Access — Brute Force (T1110)",
    "open_ssh": "Initial Access — Exposed Remote Service (T1133)",
    "open_ftp": "Initial Access — Exposed Remote Service (T1133)",
    "root_login": "Privilege Escalation — Valid Accounts: Root (T1078.003)",
    "weak_firewall": "Defense Evasion — Impair Defenses (T1562)",
}


def classify(finding_type: str) -> str:
    """Return MITRE-style classification for a finding type."""
    return THREAT_CATEGORIES.get(finding_type, "Unknown Threat Category")
