"""IOC Extractor — automatically extracts Indicators of Compromise from evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(slots=True)
class IOCReport:
    ip_addresses: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    file_hashes: list[str] = field(default_factory=list)
    suspicious_files: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)

    @property
    def total_iocs(self) -> int:
        return (
            len(self.ip_addresses)
            + len(self.domains)
            + len(self.urls)
            + len(self.email_addresses)
            + len(self.file_hashes)
            + len(self.suspicious_files)
            + len(self.cves)
            + len(self.user_agents)
            + len(self.ports)
        )

    @property
    def has_iocs(self) -> bool:
        return self.total_iocs > 0


# Private / reserved IP ranges to exclude from suspicious IP reporting
_PRIVATE_IP_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.)"
)

# Common non-suspicious domains to filter out
_BENIGN_DOMAINS = {
    "localhost", "example.com", "example.org", "example.net",
    "localdomain", "invalid", "test", "local",
}

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})\b"
)

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

_EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

_MD5_PATTERN = re.compile(r"\b([a-fA-F0-9]{32})\b")
_SHA1_PATTERN = re.compile(r"\b([a-fA-F0-9]{40})\b")
_SHA256_PATTERN = re.compile(r"\b([a-fA-F0-9]{64})\b")

_SUSPICIOUS_FILE_PATTERNS = re.compile(
    r"(/tmp/[^\s\"']+\.(sh|py|pl|rb|exe|elf|bin|php|jsp|war))"
    r"|(/var/tmp/[^\s\"']+)"
    r"|(/dev/shm/[^\s\"']+)"
    r"|(\./[^\s\"']+\.(sh|py|pl|rb|exe|elf|bin))"
    r"|(/root/\.[^\s\"']+)"
    r"|(/home/[^\s\"']+/\.(?!bash|profile|ssh)[^\s\"']+)",
    re.IGNORECASE,
)

_CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)

_USER_AGENT_PATTERN = re.compile(
    r"(?:User-Agent|user.agent)[:\s]+([^\n\r]{10,200})",
    re.IGNORECASE,
)

_PORT_PATTERN = re.compile(r"\b(\d{1,5})/(tcp|udp)\s+open\b")


class IOCExtractor:
    """Extracts Indicators of Compromise from raw evidence."""

    def extract(self, raw_evidence: str, include_private_ips: bool = False) -> IOCReport:
        """Extract all IOC types from the provided evidence text."""
        report = IOCReport()

        report.ip_addresses = self._extract_ips(raw_evidence, include_private_ips)
        report.domains = self._extract_domains(raw_evidence)
        report.urls = self._extract_urls(raw_evidence)
        report.email_addresses = self._extract_emails(raw_evidence)
        report.file_hashes = self._extract_hashes(raw_evidence)
        report.suspicious_files = self._extract_suspicious_files(raw_evidence)
        report.cves = self._extract_cves(raw_evidence)
        report.user_agents = self._extract_user_agents(raw_evidence)
        report.ports = self._extract_open_ports(raw_evidence)

        return report

    def _extract_ips(self, text: str, include_private: bool) -> list[str]:
        """Extract unique IP addresses, optionally filtering private ranges."""
        ips = _IP_PATTERN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for ip in ips:
            if ip in seen:
                continue
            # Validate each octet is 0-255
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                if include_private or not _PRIVATE_IP_RANGES.match(ip):
                    seen.add(ip)
                    result.append(ip)
        return result

    def _extract_domains(self, text: str) -> list[str]:
        """Extract unique domain names, filtering common benign entries."""
        domains = _DOMAIN_PATTERN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for domain in domains:
            d_lower = domain.lower()
            if d_lower in seen or d_lower in _BENIGN_DOMAINS:
                continue
            # Filter out things that look like version numbers or IPs
            if re.match(r"^\d+\.\d+\.\d+", domain):
                continue
            seen.add(d_lower)
            result.append(domain)
        return result

    def _extract_urls(self, text: str) -> list[str]:
        """Extract unique URLs."""
        urls = _URL_PATTERN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    def _extract_emails(self, text: str) -> list[str]:
        """Extract unique email addresses."""
        emails = _EMAIL_PATTERN.findall(text)
        return list(dict.fromkeys(e.lower() for e in emails))

    def _extract_hashes(self, text: str) -> list[str]:
        """Extract file hashes (MD5, SHA1, SHA256)."""
        hashes: list[str] = []
        seen: set[str] = set()

        # SHA256 first (longest), then SHA1, then MD5
        for pattern, label in [
            (_SHA256_PATTERN, "SHA256"),
            (_SHA1_PATTERN, "SHA1"),
            (_MD5_PATTERN, "MD5"),
        ]:
            for match in pattern.findall(text):
                lower = match.lower()
                if lower not in seen:
                    # Filter out hex strings that are all the same digit (unlikely hash)
                    if len(set(lower)) > 3:
                        seen.add(lower)
                        hashes.append(f"{label}:{match}")
        return hashes

    def _extract_suspicious_files(self, text: str) -> list[str]:
        """Extract suspicious file paths (tmp, dev/shm, hidden files)."""
        matches = _SUSPICIOUS_FILE_PATTERNS.findall(text)
        files: list[str] = []
        seen: set[str] = set()
        for match_groups in matches:
            for m in match_groups:
                if m and m not in seen:
                    seen.add(m)
                    files.append(m)
        return files

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE identifiers."""
        cves = _CVE_PATTERN.findall(text)
        return list(dict.fromkeys(c.upper() for c in cves))

    def _extract_user_agents(self, text: str) -> list[str]:
        """Extract user-agent strings."""
        agents = _USER_AGENT_PATTERN.findall(text)
        return list(dict.fromkeys(a.strip() for a in agents))[:10]

    def _extract_open_ports(self, text: str) -> list[str]:
        """Extract open ports from nmap-style output."""
        matches = _PORT_PATTERN.findall(text)
        return list(dict.fromkeys(f"{port}/{proto}" for port, proto in matches))


def format_ioc_report(report: IOCReport) -> str:
    """Format IOC report for display or prompt injection."""
    if not report.has_iocs:
        return "No Indicators of Compromise extracted."

    sections: list[str] = []

    if report.ip_addresses:
        sections.append(
            "IP Addresses (External):\n" + "\n".join(f"  • {ip}" for ip in report.ip_addresses[:20])
        )
    if report.domains:
        sections.append(
            "Domains:\n" + "\n".join(f"  • {d}" for d in report.domains[:20])
        )
    if report.urls:
        sections.append(
            "URLs:\n" + "\n".join(f"  • {u}" for u in report.urls[:15])
        )
    if report.email_addresses:
        sections.append(
            "Email Addresses:\n" + "\n".join(f"  • {e}" for e in report.email_addresses[:10])
        )
    if report.file_hashes:
        sections.append(
            "File Hashes:\n" + "\n".join(f"  • {h}" for h in report.file_hashes[:15])
        )
    if report.suspicious_files:
        sections.append(
            "Suspicious Files:\n" + "\n".join(f"  • {f}" for f in report.suspicious_files[:15])
        )
    if report.cves:
        sections.append(
            "CVE References:\n" + "\n".join(f"  • {c}" for c in report.cves[:15])
        )
    if report.user_agents:
        sections.append(
            "User Agents:\n" + "\n".join(f"  • {ua}" for ua in report.user_agents[:5])
        )
    if report.ports:
        sections.append(
            "Open Ports:\n" + "\n".join(f"  • {p}" for p in report.ports[:20])
        )

    return "\n\n".join(sections)
