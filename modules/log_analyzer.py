"""Log Analyzer Module — detects patterns in log files."""

import re
from typing import List, Dict


class LogAnalyzer:
    """Analyzes logs for suspicious patterns and anomalies."""

    @staticmethod
    def detect_failed_logins(log_content: str) -> int:
        """Count failed login attempts."""
        pattern = r"Failed password|failed password|authentication failure|Invalid user"
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        return len(matches)

    @staticmethod
    def detect_root_logins(log_content: str) -> int:
        """Count root login attempts."""
        pattern = r"root.*accepted|accepted.*root"
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        return len(matches)

    @staticmethod
    def detect_sudo_usage(log_content: str) -> int:
        """Count sudo invocations."""
        pattern = r"sudo.*COMMAND"
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        return len(matches)

    @staticmethod
    def detect_port_scans(log_content: str) -> int:
        """Detect potential port scan activity."""
        pattern = r"port scan|nmap|banner grab|connection attempt"
        matches = re.findall(pattern, log_content, re.IGNORECASE)
        return len(matches)

    @staticmethod
    def get_unique_ips(log_content: str) -> List[str]:
        """Extract unique IPs from logs."""
        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(pattern, log_content)
        return list(set(ips))


# Backward compatibility functions
def detect_brute_force(lines: list[str], threshold: int = 5) -> list[str]:
    """Return IPs with failed login attempts exceeding the threshold."""
    failed = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
    ip_counts: dict = {}

    for line in lines:
        match = failed.search(line)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return [f"{ip} ({count} attempts)" for ip, count in ip_counts.items() if count >= threshold]


def detect_root_logins(lines: list[str]) -> list[str]:
    """Return lines showing successful root logins."""
    return [line.strip() for line in lines if "Accepted" in line and "root" in line]


def detect_invalid_users(lines: list[str]) -> list[str]:
    """Return lines showing login attempts for non-existent users."""
    return [line.strip() for line in lines if "invalid user" in line.lower()]


def summarize_log(lines: list[str]) -> dict:
    """Return a quick summary dict of key indicators found in log lines."""
    return {
        "brute_force_ips": detect_brute_force(lines),
        "root_logins": detect_root_logins(lines),
        "invalid_user_attempts": detect_invalid_users(lines),
        "total_lines": len(lines),
    }

