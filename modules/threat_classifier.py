"""Threat Classifier Module — classifies severity and urgency of findings."""

from typing import Dict


class ThreatClassifier:
    """Classifies threats by severity and confidence."""

    SEVERITY_LEVELS = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }

    CONFIDENCE_LEVELS = {
        "CONFIRMED": 3,
        "PROBABLE": 2,
        "SUSPECTED": 1,
    }

    @staticmethod
    def classify_severity(keywords: str) -> str:
        """Classify severity based on keywords."""
        critical = [
            "root access",
            "remote code execution",
            "injection",
            "authentication bypass",
        ]
        high = [
            "privilege escalation",
            "credential",
            "exposed",
            "vulnerability",
        ]
        medium = ["configuration", "weak", "suspicious", "anomaly"]

        keywords_lower = keywords.lower()

        for keyword in critical:
            if keyword in keywords_lower:
                return "CRITICAL"

        for keyword in high:
            if keyword in keywords_lower:
                return "HIGH"

        for keyword in medium:
            if keyword in keywords_lower:
                return "MEDIUM"

        return "LOW"

    @staticmethod
    def classify_confidence(evidence_quality: int) -> str:
        """Classify confidence based on evidence quality (0-3 scale)."""
        if evidence_quality >= 3:
            return "CONFIRMED"
        elif evidence_quality >= 2:
            return "PROBABLE"
        else:
            return "SUSPECTED"

    @staticmethod
    def get_severity_score(severity: str) -> int:
        """Get numeric severity score."""
        return ThreatClassifier.SEVERITY_LEVELS.get(severity, 0)


# Backward compatibility constants and functions
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
