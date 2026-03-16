"""SIEM-Style Correlation Engine — correlates findings across data sources."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections import Counter


@dataclass(slots=True)
class CorrelationFinding:
    title: str
    description: str
    confidence: str  # HIGH, MEDIUM, LOW
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    data_sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


class SIEMCorrelator:
    """Correlates security events across multiple data sources."""

    def correlate(
        self,
        raw_evidence: str,
        rule_findings: list | None = None,
        ioc_ips: list[str] | None = None,
        timeline_events: list | None = None,
        mitre_mappings: list | None = None,
    ) -> list[CorrelationFinding]:
        """Run all correlation rules and return findings."""
        findings: list[CorrelationFinding] = []

        findings.extend(self._correlate_brute_force_chain(raw_evidence, ioc_ips))
        findings.extend(self._correlate_multi_source_ip(raw_evidence, ioc_ips))
        findings.extend(self._correlate_scan_to_exploit(raw_evidence))
        findings.extend(self._correlate_auth_to_lateral(raw_evidence))
        findings.extend(self._correlate_service_exposure_chain(raw_evidence, rule_findings))
        findings.extend(self._correlate_log_web_overlap(raw_evidence))
        findings.extend(self._correlate_timeline_patterns(timeline_events))

        return self._deduplicate(findings)

    def _correlate_brute_force_chain(
        self, evidence: str, ioc_ips: list[str] | None
    ) -> list[CorrelationFinding]:
        """Detect brute force followed by successful login from the same IP."""
        findings: list[CorrelationFinding] = []

        # Extract IPs from failed and successful logins
        failed_ips = re.findall(
            r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", evidence, re.IGNORECASE
        )
        success_ips = re.findall(
            r"Accepted (?:password|publickey).*from (\d+\.\d+\.\d+\.\d+)", evidence, re.IGNORECASE
        )

        overlap = set(failed_ips) & set(success_ips)
        for ip in overlap:
            fail_count = failed_ips.count(ip)
            findings.append(CorrelationFinding(
                title="Brute Force Followed by Successful Login",
                description=(
                    f"IP {ip} had {fail_count} failed login attempts "
                    f"followed by a successful authentication. This is a strong "
                    f"indicator of compromised credentials."
                ),
                confidence="HIGH",
                severity="CRITICAL",
                data_sources=["auth.log", "sshd"],
                evidence=[
                    f"{fail_count} failed logins from {ip}",
                    f"Successful login from {ip} detected",
                ],
                recommendation=(
                    f"Immediately investigate sessions from {ip}. "
                    f"Reset compromised credentials. Check for persistence mechanisms."
                ),
            ))

        return findings

    def _correlate_multi_source_ip(
        self, evidence: str, ioc_ips: list[str] | None
    ) -> list[CorrelationFinding]:
        """Detect the same IP appearing across multiple log types."""
        findings: list[CorrelationFinding] = []

        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        all_ips = ip_pattern.findall(evidence)
        ip_counts = Counter(all_ips)

        # Look for IPs that appear in different contexts
        auth_ips = set(re.findall(r"(?:Failed|Accepted|Invalid).*?(\d+\.\d+\.\d+\.\d+)", evidence, re.IGNORECASE))
        firewall_ips = set(re.findall(r"(?:UFW|iptables|DENY|DROP|BLOCK).*?(\d+\.\d+\.\d+\.\d+)", evidence, re.IGNORECASE))
        web_ips = set(re.findall(r"(\d+\.\d+\.\d+\.\d+).*?(?:GET|POST|PUT|DELETE|HTTP/)", evidence, re.IGNORECASE))

        # IPs appearing in 2+ source types are suspicious
        for ip in ip_counts:
            # Skip private ranges for cross-source correlation
            if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)", ip):
                continue
            sources = []
            if ip in auth_ips:
                sources.append("Authentication logs")
            if ip in firewall_ips:
                sources.append("Firewall logs")
            if ip in web_ips:
                sources.append("Web access logs")

            if len(sources) >= 2:
                findings.append(CorrelationFinding(
                    title="Same IP Across Multiple Log Sources",
                    description=(
                        f"IP {ip} appears in {len(sources)} different log sources: "
                        f"{', '.join(sources)}. Cross-source activity increases "
                        f"confidence this is a coordinated attack."
                    ),
                    confidence="HIGH",
                    severity="HIGH",
                    data_sources=sources,
                    evidence=[
                        f"IP {ip} seen {ip_counts[ip]} times total",
                        f"Present in: {', '.join(sources)}",
                    ],
                    recommendation=f"Block {ip} at the firewall. Investigate all activity from this IP.",
                ))

        return findings

    def _correlate_scan_to_exploit(self, evidence: str) -> list[CorrelationFinding]:
        """Detect port scan activity followed by exploit indicators."""
        findings: list[CorrelationFinding] = []

        has_scan = bool(re.search(r"Nmap scan report|port scan|SYN scan", evidence, re.IGNORECASE))
        has_exploit = bool(re.search(
            r"CVE-\d{4}-\d+|exploit|remote code execution|RCE|reverse.shell",
            evidence, re.IGNORECASE
        ))

        if has_scan and has_exploit:
            findings.append(CorrelationFinding(
                title="Reconnaissance Followed by Exploitation Indicators",
                description=(
                    "Port scanning or service discovery activity was detected alongside "
                    "exploit references or vulnerability indicators. This pattern suggests "
                    "an active attack chain progressing from reconnaissance to exploitation."
                ),
                confidence="MEDIUM",
                severity="HIGH",
                data_sources=["Network scan output", "Exploit references"],
                evidence=["Port scan activity detected", "Exploit/CVE indicators found"],
                recommendation=(
                    "Review network segmentation. Patch identified vulnerabilities immediately. "
                    "Check for signs of successful exploitation."
                ),
            ))

        return findings

    def _correlate_auth_to_lateral(self, evidence: str) -> list[CorrelationFinding]:
        """Detect successful auth followed by lateral movement indicators."""
        findings: list[CorrelationFinding] = []

        has_success = bool(re.search(r"Accepted (password|publickey)", evidence, re.IGNORECASE))
        has_lateral = bool(re.search(
            r"ssh.*from.*ssh|lateral.*mov|pivot|new.*session.*from",
            evidence, re.IGNORECASE
        ))

        if has_success and has_lateral:
            findings.append(CorrelationFinding(
                title="Authentication Followed by Lateral Movement",
                description=(
                    "Successful authentication was followed by indicators of "
                    "lateral movement. An attacker may be pivoting through the network."
                ),
                confidence="MEDIUM",
                severity="CRITICAL",
                data_sources=["Authentication logs", "Session logs"],
                evidence=["Successful login detected", "Lateral movement indicators found"],
                recommendation=(
                    "Isolate affected hosts. Review all sessions from the authenticated user. "
                    "Check for unauthorized SSH key additions."
                ),
            ))

        return findings

    def _correlate_service_exposure_chain(
        self, evidence: str, rule_findings: list | None
    ) -> list[CorrelationFinding]:
        """Correlate multiple exposed services into a compound risk finding."""
        findings: list[CorrelationFinding] = []

        exposed_services: list[str] = []
        critical_ports = {
            22: "SSH", 23: "Telnet", 3306: "MySQL", 6379: "Redis",
            3389: "RDP", 445: "SMB", 27017: "MongoDB", 9200: "Elasticsearch",
        }
        for port, service in critical_ports.items():
            if re.search(rf"\b{port}/(tcp|udp)\s+open\b", evidence):
                exposed_services.append(f"{service} (port {port})")

        if len(exposed_services) >= 3:
            findings.append(CorrelationFinding(
                title="Multiple Critical Services Exposed",
                description=(
                    f"{len(exposed_services)} critical services are publicly exposed: "
                    f"{', '.join(exposed_services)}. This significantly increases the "
                    f"attack surface and indicates weak network segmentation."
                ),
                confidence="HIGH",
                severity="CRITICAL",
                data_sources=["Port scan results"],
                evidence=[f"Exposed: {s}" for s in exposed_services],
                recommendation=(
                    "Implement network segmentation. Restrict access to critical services "
                    "via firewall rules. Apply defense-in-depth strategy."
                ),
            ))

        return findings

    def _correlate_log_web_overlap(self, evidence: str) -> list[CorrelationFinding]:
        """Detect combined web enumeration and authentication attacks."""
        findings: list[CorrelationFinding] = []

        web_enum = len(re.findall(r"\b(401|403|404)\b", evidence))
        admin_probing = bool(re.search(
            r"/(admin|wp-admin|phpmyadmin|console|panel|dashboard)", evidence, re.IGNORECASE
        ))
        auth_attacks = len(re.findall(r"Failed password|authentication failure", evidence, re.IGNORECASE))

        if web_enum >= 5 and auth_attacks >= 3:
            findings.append(CorrelationFinding(
                title="Combined Web and Authentication Attack",
                description=(
                    f"Web enumeration ({web_enum} error codes) and "
                    f"authentication attacks ({auth_attacks} failures) detected in the "
                    f"same evidence window. This suggests a multi-vector attack."
                ),
                confidence="HIGH" if admin_probing else "MEDIUM",
                severity="HIGH",
                data_sources=["Web access logs", "Authentication logs"],
                evidence=[
                    f"{web_enum} HTTP error status codes",
                    f"{auth_attacks} authentication failures",
                ] + (["Admin endpoint probing detected"] if admin_probing else []),
                recommendation=(
                    "Deploy WAF rules. Enable rate limiting. "
                    "Review authentication hardening and account lockout policies."
                ),
            ))

        return findings

    def _correlate_timeline_patterns(self, timeline_events: list | None) -> list[CorrelationFinding]:
        """Detect suspicious patterns in timeline event sequences."""
        if not timeline_events or len(timeline_events) < 3:
            return []

        findings: list[CorrelationFinding] = []

        # Detect rapid-fire events from same IP (speed indicates automation)
        from collections import Counter
        event_types = Counter(e.event_type for e in timeline_events if hasattr(e, "event_type"))

        failed_count = event_types.get("Failed SSH Login", 0) + event_types.get("Authentication Failure", 0)
        if failed_count >= 10:
            findings.append(CorrelationFinding(
                title="High-Velocity Authentication Attacks",
                description=(
                    f"{failed_count} authentication failures detected in the timeline. "
                    f"The volume and speed indicate automated tooling (e.g., Hydra, Medusa)."
                ),
                confidence="HIGH",
                severity="HIGH",
                data_sources=["Timeline analysis"],
                evidence=[f"{failed_count} rapid authentication failures"],
                recommendation="Deploy fail2ban or equivalent. Consider geo-blocking.",
            ))

        return findings

    def _deduplicate(self, findings: list[CorrelationFinding]) -> list[CorrelationFinding]:
        """Remove duplicate correlation findings by title."""
        seen: set[str] = set()
        unique: list[CorrelationFinding] = []
        for f in findings:
            if f.title not in seen:
                seen.add(f.title)
                unique.append(f)
        return unique


def format_correlation_findings(findings: list[CorrelationFinding]) -> str:
    """Format correlation findings for display or prompt injection."""
    if not findings:
        return "No cross-source correlations identified."
    lines: list[str] = []
    for f in findings:
        evidence_str = "\n  ".join(f"• {e}" for e in f.evidence)
        lines.append(
            f"[{f.severity}] {f.title}\n"
            f"  Confidence: {f.confidence}\n"
            f"  Sources: {', '.join(f.data_sources)}\n"
            f"  Evidence:\n  {evidence_str}\n"
            f"  Recommendation: {f.recommendation}"
        )
    return "\n\n".join(lines)
