"""Investigate command — deep analytical investigation of a single artifact."""

from __future__ import annotations

import os
from pathlib import Path

from modules.file_loader import FileLoader
from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter


_ARTIFACT_HINTS: dict[str, str] = {
    "auth.log":      "Linux authentication log (SSH logins, sudo, PAM events)",
    "auth":          "Linux authentication log (SSH logins, sudo, PAM events)",
    "syslog":        "System log — kernel, daemon, cron, and network events",
    "kern.log":      "Kernel log — hardware faults, module loads, OOM events",
    "access.log":    "Web server access log (Apache/Nginx HTTP requests)",
    "error.log":     "Web server error log (Apache/Nginx errors and warnings)",
    "secure":        "RHEL/CentOS security log (equivalent to auth.log)",
    "fail2ban.log":  "fail2ban event log — bans, unbans, detection events",
    "ufw.log":       "UFW firewall log — allowed and blocked connections",
    "dpkg.log":      "Debian package manager log — installs, removals, upgrades",
    "sshd_config":   "OpenSSH daemon configuration file",
    "nginx.conf":    "Nginx web server configuration",
    "apache2.conf":  "Apache web server configuration",
    "httpd.conf":    "Apache web server configuration",
    "my.cnf":        "MySQL/MariaDB configuration",
    "mysqld.cnf":    "MySQL/MariaDB server configuration",
    "php.ini":       "PHP runtime configuration",
    "sudoers":       "Sudo privilege configuration — who can run what as root",
    "crontab":       "Scheduled task configuration — potential persistence mechanism",
    "passwd":        "Linux user account database (/etc/passwd)",
    "shadow":        "Linux password hash database (/etc/shadow)",
    "hosts.allow":   "TCP Wrappers allow list",
    "hosts.deny":    "TCP Wrappers deny list",
}


def _classify_artifact(file_path: str) -> str:
    """Return a hint string describing the artifact type from its filename."""
    name = Path(file_path).name.lower()
    # Exact match first
    if name in _ARTIFACT_HINTS:
        return _ARTIFACT_HINTS[name]
    # Substring match
    for key, description in _ARTIFACT_HINTS.items():
        if key in name:
            return description
    # Extension fallback
    suffix = Path(file_path).suffix.lower()
    if suffix in (".log", ".txt"):
        return "Log or text file — classify by content"
    if suffix in (".conf", ".cfg", ".ini", ".cnf"):
        return "Configuration file — review for insecure directives"
    if suffix == ".pdf":
        return "PDF document — review for extracted security content"
    return "Unknown artifact type — classify from content"


def run_investigate(file_path: str, system_prompt: str) -> AnalysisResult:
    """
    Perform a deep security investigation of an artifact file.

    Differs from the basic 'analyze' command by:
    - Detecting artifact type and tailoring the AI task instruction
    - Performing pre-analysis statistics on suspicious patterns
    - Including line-level threat indicators in the evidence
    - Providing richer context for correlation with prior history
    """
    formatter = OutputFormatter()

    if not os.path.isfile(file_path):
        return AnalysisResult(
            report=f"[!] File not found or is not a regular file: {file_path}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    artifact_hint = _classify_artifact(file_path)
    formatter.print_info(f"[Investigate] Artifact: {file_path}")
    formatter.print_info(f"[Investigate] Classified as: {artifact_hint}")

    content = FileLoader.load(file_path)

    if content is None or content.startswith("[!]") or not content.strip():
        msg = content or f"[!] Could not read file: {file_path}"
        return AnalysisResult(
            report=msg,
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    # Pre-analysis: count indicators to surface to the analyst
    lines = content.splitlines()
    total_lines = len(lines)
    formatter.print_info(f"[Investigate] {total_lines} lines loaded — scanning for indicators...")

    indicators = _extract_indicators(lines)
    indicator_block = _format_indicator_block(indicators, total_lines)

    # Combine artifact metadata + indicators + raw content
    evidence_parts = [
        f"=== ARTIFACT METADATA ===",
        f"File: {file_path}",
        f"Type: {artifact_hint}",
        f"Total lines: {total_lines}",
        "",
        indicator_block,
        "",
        "=== ARTIFACT CONTENT ===",
        content,
    ]
    raw_evidence = "\n".join(evidence_parts)

    task_instruction = (
        f"You are performing a DEEP INVESTIGATION of the following artifact:\n"
        f"  File: {Path(file_path).name}\n"
        f"  Type: {artifact_hint}\n\n"
        "Investigation requirements:\n"
        "1. Classify the exact artifact type from content, confirming or correcting the hint above.\n"
        "2. Extract ALL security-relevant findings with line references where possible.\n"
        "3. For log files: identify attack sequences, brute-force patterns, privilege escalation traces, "
        "anomalous IPs/users, timeline of suspicious events.\n"
        "4. For configuration files: flag every dangerous directive "
        "(e.g., PermitRootLogin yes, expose_php On, bind-address 0.0.0.0) "
        "and provide the correct secure value.\n"
        "5. Link each finding to a MITRE ATT&CK technique ID where applicable.\n"
        "6. Assess attacker intent if log-based — what are they trying to achieve?\n"
        "7. Provide prioritized remediation and hardening specific to the artifact type.\n"
        "8. Note any correlation with prior scan history provided in context."
    )

    return run_intelligence_analysis(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        command_name="investigate",
        target=file_path,
        task_instruction=task_instruction,
    )


# ---------------------------------------------------------------------------
# Indicator extraction helpers
# ---------------------------------------------------------------------------

import re


_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Failed SSH login",    re.compile(r"failed password|invalid user|authentication failure", re.I)),
    ("Accepted SSH login",  re.compile(r"accepted (password|publickey)", re.I)),
    ("sudo event",          re.compile(r"\bsudo\b.*TTY=", re.I)),
    ("Connection refused",  re.compile(r"connection refused", re.I)),
    ("Port scan indicator", re.compile(r"SYN.*RST|nmap|masscan|port scan", re.I)),
    ("Privilege escalation",re.compile(r"su\[|pam_unix.*root|uid=0", re.I)),
    ("Malware indicator",   re.compile(r"base64|eval\(|/tmp/[a-z0-9]{6,}|\.sh.*curl|wget.*pipe", re.I)),
    ("HTTP attack pattern", re.compile(r"\.\.\/|%2e%2e|<script|union.*select|etc/passwd", re.I)),
    ("Banned/blocked IP",   re.compile(r"ban|block|DROP.*SRC=|REJECT.*SRC=", re.I)),
    ("Error/critical event",re.compile(r"\b(error|critical|emerg|alert|crit)\b", re.I)),
]


def _extract_indicators(lines: list[str]) -> dict[str, list[str]]:
    """Scan content lines for pre-defined threat indicator patterns."""
    found: dict[str, list[str]] = {label: [] for label, _ in _PATTERNS}
    for i, line in enumerate(lines, start=1):
        for label, pattern in _PATTERNS:
            if pattern.search(line):
                # Store at most 10 example lines per category
                if len(found[label]) < 10:
                    found[label].append(f"  L{i}: {line.strip()[:200]}")
    return found


def _format_indicator_block(indicators: dict[str, list[str]], total_lines: int) -> str:
    """Format the pre-analysis indicator summary as a readable section."""
    lines_out = ["=== PRE-ANALYSIS INDICATOR SCAN ==="]
    any_found = False
    for label, matches in indicators.items():
        if matches:
            any_found = True
            lines_out.append(f"\n[{label}] ({len(matches)} example{'s' if len(matches) != 1 else ''} shown)")
            lines_out.extend(matches)
    if not any_found:
        lines_out.append("No common threat indicators matched — review content manually.")
    return "\n".join(lines_out)
