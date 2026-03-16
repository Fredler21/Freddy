"""Security Mentor — adds educational context to security findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class LearningNote:
    topic: str
    explanation: str
    real_world_context: str
    further_reading: str


# Educational content keyed by detection patterns
_LEARNING_NOTES: dict[str, LearningNote] = {
    "ssh_exposure": LearningNote(
        topic="SSH Exposure (Port 22)",
        explanation=(
            "Port 22 is used by the Secure Shell (SSH) protocol for encrypted remote access. "
            "When exposed to the internet, SSH becomes a primary target for automated brute-force attacks. "
            "Attackers use tools like Hydra and Medusa to attempt thousands of password combinations per minute."
        ),
        real_world_context=(
            "SSH brute-force attacks are among the most common threats observed in SOC environments. "
            "The Mirai botnet and its variants routinely scan the internet for exposed SSH services. "
            "In 2023, CISA reported SSH-related compromises as one of the top initial access vectors."
        ),
        further_reading="NIST SP 800-123 (Server Security) | CIS Benchmark for SSH | MITRE T1110, T1133",
    ),
    "brute_force": LearningNote(
        topic="Brute Force Attacks",
        explanation=(
            "A brute-force attack systematically tries all possible passwords or credentials "
            "until the correct one is found. Variants include password spraying (trying common "
            "passwords across many accounts) and credential stuffing (using leaked credentials)."
        ),
        real_world_context=(
            "In a real SOC, failed login spikes trigger alerts in SIEM platforms like Splunk, "
            "Elastic SIEM, or Microsoft Sentinel. Analysts correlate source IPs with threat intel "
            "feeds to determine if the attack is part of a botnet campaign."
        ),
        further_reading="MITRE T1110 | OWASP Testing Guide: Authentication | NIST SP 800-63B",
    ),
    "weak_tls": LearningNote(
        topic="Weak TLS/SSL Configuration",
        explanation=(
            "TLS (Transport Layer Security) encrypts data in transit. Older versions like TLS 1.0 "
            "and 1.1, and weak ciphers like RC4 and DES, have known vulnerabilities that allow "
            "attackers to decrypt traffic through attacks like BEAST, POODLE, and SWEET32."
        ),
        real_world_context=(
            "PCI DSS requires TLS 1.2 or higher for credit card transactions. Many compliance "
            "frameworks (SOC 2, HIPAA, FedRAMP) also mandate strong TLS configurations. "
            "SOC analysts regularly verify TLS posture during security assessments."
        ),
        further_reading="NIST SP 800-52 Rev 2 | Mozilla SSL Configuration Generator | SSL Labs Test",
    ),
    "open_ports": LearningNote(
        topic="Open Ports and Attack Surface",
        explanation=(
            "Every open port represents a potential entry point for attackers. Unnecessary open "
            "ports increase the attack surface. Critical services like databases (MySQL 3306, "
            "Redis 6379, MongoDB 27017) should never be exposed to the public internet."
        ),
        real_world_context=(
            "Shodan and Censys scans reveal millions of exposed database services worldwide. "
            "In 2020, over 75,000 unsecured Elasticsearch instances were found exposed, leading "
            "to massive data breaches. SOC analysts use port scan data as a baseline for monitoring."
        ),
        further_reading="CIS Benchmarks | SANS Port Security Guide | MITRE T1046",
    ),
    "firewall_inactive": LearningNote(
        topic="Firewall Configuration",
        explanation=(
            "A firewall controls incoming and outgoing network traffic based on security rules. "
            "An inactive or misconfigured firewall leaves every service exposed. "
            "Defense-in-depth requires host-based firewalls even behind network firewalls."
        ),
        real_world_context=(
            "Host-based firewalls (UFW, iptables, Windows Firewall) are a compliance requirement "
            "in most security frameworks. SOC teams verify firewall rules during incident response "
            "to understand what traffic was allowed during an attack."
        ),
        further_reading="NIST SP 800-41 Rev 1 | CIS Benchmark: Firewall | UFW/iptables Documentation",
    ),
    "admin_exposure": LearningNote(
        topic="Administrative Endpoint Exposure",
        explanation=(
            "Admin panels (/admin, /wp-admin, /phpmyadmin) are high-value targets. "
            "Automated scanners probe for these endpoints constantly. "
            "Exposing them without proper access controls invites brute-force and exploitation."
        ),
        real_world_context=(
            "Web application firewalls (WAFs) typically include rules to detect admin path probing. "
            "In production SOCs, alerts fire when scanners like Nikto or DirBuster patterns are "
            "detected hitting admin endpoints."
        ),
        further_reading="OWASP Admin Interface Protection | MITRE T1190 | CWE-306",
    ),
    "missing_headers": LearningNote(
        topic="HTTP Security Headers",
        explanation=(
            "Security headers like HSTS, CSP, X-Frame-Options, and X-Content-Type-Options "
            "protect against common web attacks: clickjacking, XSS, MIME sniffing, and "
            "protocol downgrade attacks. Missing headers leave users vulnerable."
        ),
        real_world_context=(
            "Security header analysis is part of every web application penetration test. "
            "Tools like Mozilla Observatory and securityheaders.com grade sites on header implementation. "
            "OWASP includes header verification in their testing methodology."
        ),
        further_reading="OWASP Secure Headers | Mozilla Web Security Guidelines | securityheaders.com",
    ),
    "container_security": LearningNote(
        topic="Container Security",
        explanation=(
            "Running Docker containers in privileged mode or with ports bound to 0.0.0.0 "
            "breaks container isolation. Privileged containers can access the host kernel and "
            "file system, essentially providing root access to the host."
        ),
        real_world_context=(
            "Container escapes are a growing attack vector. CVE-2019-5736 allowed containers "
            "to overwrite the host runc binary. SOC teams monitor container configurations "
            "as part of cloud security posture management (CSPM)."
        ),
        further_reading="NIST SP 800-190 (Container Security) | CIS Docker Benchmark | MITRE T1610",
    ),
    "sudo_misuse": LearningNote(
        topic="Sudo Misconfiguration",
        explanation=(
            "NOPASSWD ALL in sudoers grants unrestricted passwordless root access, "
            "completely eliminating privilege separation. Any process running as that "
            "user can execute any command as root without authentication."
        ),
        real_world_context=(
            "Privilege escalation via sudo misconfigurations is a common finding in "
            "penetration tests. Tools like LinPEAS and sudo_killer specifically enumerate "
            "these issues. GTFOBins catalogs sudo bypass techniques."
        ),
        further_reading="MITRE T1548 | GTFOBins | CIS Sudoers Benchmark",
    ),
    "port_scan_detected": LearningNote(
        topic="Network Reconnaissance",
        explanation=(
            "Port scanning is often the first step in an attack. Tools like Nmap identify "
            "open ports, running services, and their versions to find vulnerabilities. "
            "Understanding scan techniques helps defenders detect and respond to reconnaissance."
        ),
        real_world_context=(
            "SOC analysts distinguish between legitimate vulnerability assessments and "
            "malicious scanning by checking source IP reputation, scan patterns (sequential "
            "vs random ports), and correlation with other attack indicators."
        ),
        further_reading="MITRE T1046 | Nmap Network Scanning Guide | SANS Network Forensics",
    ),
    "log_analysis": LearningNote(
        topic="Security Log Analysis",
        explanation=(
            "Logs are the foundation of security monitoring. Auth logs, syslog, web access "
            "logs, and firewall logs contain evidence of both normal activity and attacks. "
            "The ability to parse, correlate, and timeline log events is a core SOC skill."
        ),
        real_world_context=(
            "SIEM platforms ingest millions of log events daily. Analysts write detection "
            "rules (Sigma, YARA, KQL) to automatically flag suspicious patterns. "
            "Log retention and analysis are required by most compliance frameworks."
        ),
        further_reading="NIST SP 800-92 (Log Management) | Sigma Rules Project | ELK Stack Documentation",
    ),
    "dns_issues": LearningNote(
        topic="DNS Security",
        explanation=(
            "DNS misconfigurations can enable zone transfers (leaking all DNS records), "
            "cache poisoning, and domain hijacking. DNSSEC provides cryptographic authentication "
            "of DNS responses but requires proper configuration."
        ),
        real_world_context=(
            "DNS is a frequent attack vector — DNS tunneling for data exfiltration, "
            "DNS rebinding for internal network access, and BGP hijacking for DNS "
            "redirection are all techniques seen in real-world attacks."
        ),
        further_reading="NIST SP 800-81 (DNS Security) | MITRE T1071.004 | RFC 4033 (DNSSEC)",
    ),
}


class SecurityMentor:
    """Provides educational learning notes alongside security findings."""

    def generate_notes(
        self,
        rule_findings: list | None = None,
        mitre_mappings: list | None = None,
        raw_evidence: str = "",
    ) -> list[LearningNote]:
        """Generate learning notes based on detected findings."""
        notes: list[LearningNote] = []
        used_topics: set[str] = set()

        if rule_findings:
            for finding in rule_findings:
                title = getattr(finding, "title", "").lower()
                topic_key = self._match_topic(title)
                if topic_key and topic_key not in used_topics:
                    used_topics.add(topic_key)
                    notes.append(_LEARNING_NOTES[topic_key])

        # Also check evidence directly for educational opportunities
        evidence_lower = raw_evidence.lower()
        evidence_topics = {
            "ssh_exposure": ["ssh", "port 22", "openssh"],
            "brute_force": ["failed password", "brute force", "invalid user"],
            "weak_tls": ["tlsv1.0", "sslv3", "rc4", "weak cipher"],
            "firewall_inactive": ["firewall", "ufw", "inactive"],
            "container_security": ["docker", "container", "privileged"],
            "dns_issues": ["dns", "zone transfer", "nslookup"],
            "log_analysis": ["syslog", "auth.log", "journalctl"],
            "port_scan_detected": ["nmap", "port scan", "syn scan"],
        }

        for topic_key, keywords in evidence_topics.items():
            if topic_key in used_topics:
                continue
            for kw in keywords:
                if kw in evidence_lower:
                    if topic_key in _LEARNING_NOTES:
                        used_topics.add(topic_key)
                        notes.append(_LEARNING_NOTES[topic_key])
                    break

        return notes[:5]  # Limit to 5 most relevant notes

    def _match_topic(self, finding_title: str) -> str | None:
        """Match a rule finding title to a learning note topic."""
        topic_keywords = {
            "ssh_exposure": ["ssh", "port 22"],
            "brute_force": ["brute", "failed login", "credential"],
            "weak_tls": ["tls", "ssl", "cipher"],
            "open_ports": ["port", "exposure", "service"],
            "firewall_inactive": ["firewall", "inactive", "iptables"],
            "admin_exposure": ["admin", "endpoint", "panel"],
            "missing_headers": ["header", "hsts", "csp", "x-frame"],
            "container_security": ["docker", "container", "privileged"],
            "sudo_misuse": ["sudo", "nopasswd"],
        }

        for topic_key, keywords in topic_keywords.items():
            if any(kw in finding_title for kw in keywords):
                return topic_key
        return None


def format_learning_notes(notes: list[LearningNote]) -> str:
    """Format learning notes for terminal display."""
    if not notes:
        return ""
    lines: list[str] = []
    for note in notes:
        lines.append(
            f"📚 {note.topic}\n"
            f"   {note.explanation}\n\n"
            f"   Real-World Context:\n"
            f"   {note.real_world_context}\n\n"
            f"   Further Reading: {note.further_reading}"
        )
    return "\n\n" + "\n\n".join(lines)
