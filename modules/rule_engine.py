from __future__ import annotations

"""Rule engine for deterministic pre-AI findings."""

from dataclasses import asdict, dataclass
import re


@dataclass(slots=True)
class RuleFinding:
    title: str
    severity: str
    confidence: str
    rationale: str
    recommended_inspection_area: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class RuleEngine:
    """Applies reusable security heuristics to raw scan and log data."""

    SERVICE_PORT_RULES = {
        22: ("Possible public SSH exposure", "HIGH", "Inspect SSH configuration, network exposure, and auth controls."),
        21: ("Possible FTP exposure", "HIGH", "Inspect FTP necessity, encryption, and anonymous access controls."),
        23: ("Telnet exposure", "CRITICAL", "Inspect legacy remote administration exposure and replacement options."),
        3306: ("Possible MySQL exposure", "HIGH", "Inspect MySQL bind address, firewall rules, and remote grants."),
        5432: ("Possible PostgreSQL exposure", "HIGH", "Inspect PostgreSQL bind settings, pg_hba rules, and network restrictions."),
        6379: ("Possible Redis exposure", "CRITICAL", "Inspect Redis bind settings, protected mode, ACLs, and TLS."),
        9200: ("Possible Elasticsearch exposure", "CRITICAL", "Inspect cluster exposure, auth, and data access controls."),
    }

    def evaluate(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        findings.extend(self._detect_exposed_ports(raw_data))
        findings.extend(self._detect_failed_logins(raw_data))
        findings.extend(self._detect_web_enumeration(raw_data))
        findings.extend(self._detect_admin_paths(raw_data))
        return self._deduplicate(findings)

    def _detect_exposed_ports(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        for port, (title, severity, rationale) in self.SERVICE_PORT_RULES.items():
            if self._port_visible(raw_data, port):
                findings.append(
                    RuleFinding(
                        title=title,
                        severity=severity,
                        confidence="medium",
                        rationale=f"Port {port} appears in the evidence, suggesting the related service may be listening or reachable. {rationale}",
                        recommended_inspection_area=f"Port {port} service configuration and firewall exposure",
                    )
                )
        return findings

    def _detect_failed_logins(self, raw_data: str) -> list[RuleFinding]:
        failed_patterns = re.findall(r"Failed password|authentication failure|Invalid user", raw_data, re.IGNORECASE)
        if len(failed_patterns) >= 5:
            return [
                RuleFinding(
                    title="Possible brute-force activity",
                    severity="HIGH",
                    confidence="high",
                    rationale=f"Detected {len(failed_patterns)} failed authentication indicators in the provided evidence.",
                    recommended_inspection_area="Authentication logs, SSH settings, and rate-limiting controls",
                )
            ]
        return []

    def _detect_web_enumeration(self, raw_data: str) -> list[RuleFinding]:
        status_hits = re.findall(r"\b(401|403|404)\b", raw_data)
        if len(status_hits) >= 6:
            return [
                RuleFinding(
                    title="Possible web enumeration or forced browsing",
                    severity="MEDIUM",
                    confidence="medium",
                    rationale=f"Observed repeated denial or not-found status codes ({len(status_hits)} instances), which can indicate automated path discovery.",
                    recommended_inspection_area="Web access logs, WAF rules, and sensitive route protections",
                )
            ]
        return []

    def _detect_admin_paths(self, raw_data: str) -> list[RuleFinding]:
        admin_pattern = re.compile(r"/(admin|administrator|manage|console|wp-admin|phpmyadmin|actuator|dashboard)\b", re.IGNORECASE)
        if admin_pattern.search(raw_data):
            return [
                RuleFinding(
                    title="Possible administrative exposure",
                    severity="HIGH",
                    confidence="medium",
                    rationale="The evidence references admin-like endpoints that may be publicly reachable or actively probed.",
                    recommended_inspection_area="Administrative routes, access control policies, and external exposure",
                )
            ]
        return []

    @staticmethod
    def _port_visible(raw_data: str, port: int) -> bool:
        patterns = [
            rf"\b{port}/tcp\b",
            rf"\b{port}/udp\b",
            rf":{port}\b",
            rf"port\s+{port}\b",
        ]
        return any(re.search(pattern, raw_data, re.IGNORECASE) for pattern in patterns)

    @staticmethod
    def _deduplicate(findings: list[RuleFinding]) -> list[RuleFinding]:
        seen: set[str] = set()
        deduped: list[RuleFinding] = []
        for finding in findings:
            if finding.title in seen:
                continue
            deduped.append(finding)
            seen.add(finding.title)
        return deduped
