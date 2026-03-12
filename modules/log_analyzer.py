"""Log analyzer module — detects brute force, suspicious logins, and anomalies."""

import re
from collections import Counter


def detect_brute_force(lines: list[str], threshold: int = 5) -> list[str]:
    """Return IPs with failed login attempts exceeding the threshold."""
    failed = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
    ip_counts: Counter = Counter()

    for line in lines:
        match = failed.search(line)
        if match:
            ip_counts[match.group(1)] += 1

    return [f"{ip} ({count} attempts)" for ip, count in ip_counts.items() if count >= threshold]


def detect_root_logins(lines: list[str]) -> list[str]:
    """Return lines showing successful root logins."""
    return [line.strip() for line in lines if "Accepted" in line and "root" in line]
