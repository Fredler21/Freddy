"""Incident Timeline Reconstructor — builds attack timelines from log evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class TimelineEvent:
    timestamp: str
    event_type: str
    description: str
    source_ip: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO


# Patterns that match common log formats and extract timestamp + event info
_TIMESTAMP_PATTERNS = [
    # syslog: Mar 14 02:11:04
    re.compile(
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<rest>.+)"
    ),
    # ISO: 2026-03-14T02:11:04
    re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?P<rest>.+)"
    ),
    # Apache/Nginx combined: [14/Mar/2026:02:11:04 +0000]
    re.compile(
        r"\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]?\d{4})\]\s+"
        r"(?P<rest>.+)"
    ),
    # Generic HH:MM:SS
    re.compile(
        r"(?P<ts>\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)"
    ),
]

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Event classification rules
_EVENT_RULES: list[dict] = [
    {
        "type": "Failed SSH Login",
        "patterns": [re.compile(r"Failed password", re.IGNORECASE)],
        "severity": "HIGH",
    },
    {
        "type": "Invalid User Attempt",
        "patterns": [re.compile(r"Invalid user", re.IGNORECASE)],
        "severity": "HIGH",
    },
    {
        "type": "Successful Login",
        "patterns": [re.compile(r"Accepted (password|publickey)", re.IGNORECASE)],
        "severity": "MEDIUM",
    },
    {
        "type": "Root Login",
        "patterns": [re.compile(r"(Accepted|session opened).*root", re.IGNORECASE)],
        "severity": "CRITICAL",
    },
    {
        "type": "Sudo Command Executed",
        "patterns": [re.compile(r"sudo.*COMMAND", re.IGNORECASE)],
        "severity": "MEDIUM",
    },
    {
        "type": "Session Opened",
        "patterns": [re.compile(r"session opened", re.IGNORECASE)],
        "severity": "INFO",
    },
    {
        "type": "Session Closed",
        "patterns": [re.compile(r"session closed", re.IGNORECASE)],
        "severity": "INFO",
    },
    {
        "type": "Service Started",
        "patterns": [re.compile(r"(Started|starting)\s+\w+", re.IGNORECASE)],
        "severity": "INFO",
    },
    {
        "type": "Service Stopped",
        "patterns": [re.compile(r"(Stopped|stopping)\s+\w+", re.IGNORECASE)],
        "severity": "LOW",
    },
    {
        "type": "Firewall Block",
        "patterns": [re.compile(r"(UFW BLOCK|iptables.*DROP|DENIED)", re.IGNORECASE)],
        "severity": "MEDIUM",
    },
    {
        "type": "Connection Established",
        "patterns": [re.compile(r"(connection|Connection)\s+(from|established)", re.IGNORECASE)],
        "severity": "INFO",
    },
    {
        "type": "Authentication Failure",
        "patterns": [re.compile(r"authentication failure|auth.*fail", re.IGNORECASE)],
        "severity": "HIGH",
    },
    {
        "type": "Privilege Escalation Attempt",
        "patterns": [re.compile(r"(NOPASSWD|privilege|escalat|setuid)", re.IGNORECASE)],
        "severity": "CRITICAL",
    },
    {
        "type": "Suspicious File Access",
        "patterns": [re.compile(r"/tmp/.*\.(sh|py|pl|exe)|/etc/(passwd|shadow)", re.IGNORECASE)],
        "severity": "HIGH",
    },
    {
        "type": "Web Request - Client Error",
        "patterns": [re.compile(r"\" (40[0-9]) ")],
        "severity": "LOW",
    },
    {
        "type": "Web Request - Server Error",
        "patterns": [re.compile(r"\" (50[0-9]) ")],
        "severity": "MEDIUM",
    },
    {
        "type": "Potential Port Scan",
        "patterns": [re.compile(r"port scan|SYN.*flood|connection attempt", re.IGNORECASE)],
        "severity": "HIGH",
    },
]


class TimelineReconstructor:
    """Reconstructs incident timelines from log data."""

    def build_timeline(self, raw_evidence: str, max_events: int = 100) -> list[TimelineEvent]:
        """Parse log evidence and build a chronological timeline of security events."""
        events: list[TimelineEvent] = []

        for line in raw_evidence.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            timestamp, remainder = self._extract_timestamp(stripped)
            if not timestamp:
                continue

            event_type, severity = self._classify_event(stripped)
            if event_type == "Unknown":
                continue

            ip_match = _IP_PATTERN.search(stripped)
            source_ip = ip_match.group(1) if ip_match else ""

            # Build a concise description
            description = remainder[:200] if remainder else stripped[:200]

            events.append(TimelineEvent(
                timestamp=timestamp,
                event_type=event_type,
                description=description,
                source_ip=source_ip,
                severity=severity,
            ))

            if len(events) >= max_events:
                break

        return events

    def _extract_timestamp(self, line: str) -> tuple[str, str]:
        """Extract timestamp from a log line. Returns (timestamp, remaining_text)."""
        for pattern in _TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                ts = match.group("ts")
                rest = match.group("rest") if "rest" in match.groupdict() else ""
                return ts, rest
        return "", ""

    def _classify_event(self, line: str) -> tuple[str, str]:
        """Classify a log line into an event type and severity."""
        for rule in _EVENT_RULES:
            for pattern in rule["patterns"]:
                if pattern.search(line):
                    return rule["type"], rule["severity"]
        return "Unknown", "INFO"

    def get_attack_phases(self, events: list[TimelineEvent]) -> list[dict]:
        """Group timeline events into attack phases for narrative reconstruction."""
        phases: list[dict] = []
        phase_map = {
            "Failed SSH Login": "Reconnaissance / Brute Force",
            "Invalid User Attempt": "Reconnaissance / Brute Force",
            "Authentication Failure": "Reconnaissance / Brute Force",
            "Potential Port Scan": "Reconnaissance / Scanning",
            "Successful Login": "Initial Access",
            "Root Login": "Privilege Escalation",
            "Sudo Command Executed": "Execution",
            "Privilege Escalation Attempt": "Privilege Escalation",
            "Suspicious File Access": "Collection / Persistence",
            "Firewall Block": "Defense Response",
            "Connection Established": "Lateral Movement",
        }

        current_phase = None
        current_events: list[TimelineEvent] = []

        for event in events:
            phase_name = phase_map.get(event.event_type, "Other Activity")
            if phase_name != current_phase:
                if current_phase and current_events:
                    phases.append({
                        "phase": current_phase,
                        "events": current_events,
                        "start": current_events[0].timestamp,
                        "end": current_events[-1].timestamp,
                    })
                current_phase = phase_name
                current_events = [event]
            else:
                current_events.append(event)

        if current_phase and current_events:
            phases.append({
                "phase": current_phase,
                "events": current_events,
                "start": current_events[0].timestamp,
                "end": current_events[-1].timestamp,
            })

        return phases


def format_timeline(events: list[TimelineEvent]) -> str:
    """Format timeline events for display or AI prompt injection."""
    if not events:
        return "No security-relevant timeline events detected."
    lines: list[str] = []
    for event in events:
        ip_part = f" from {event.source_ip}" if event.source_ip else ""
        lines.append(
            f"[{event.severity}] {event.timestamp} — {event.event_type}{ip_part}\n"
            f"  {event.description}"
        )
    return "\n\n".join(lines)


def format_timeline_compact(events: list[TimelineEvent]) -> str:
    """Format a compact timeline for terminal display."""
    if not events:
        return "No timeline events detected."
    lines: list[str] = []
    for event in events:
        ip_part = f" from {event.source_ip}" if event.source_ip else ""
        lines.append(f"{event.timestamp} — {event.event_type}{ip_part}")
    return "\n".join(lines)
