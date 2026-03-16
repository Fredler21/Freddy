"""Threat Intelligence Module — checks IPs and domains against public threat feeds."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass(slots=True)
class ThreatIntelResult:
    indicator: str
    indicator_type: str  # ip, domain, hash
    source: str  # AbuseIPDB, VirusTotal, AlienVault OTX
    reputation: str  # Malicious, Suspicious, Clean, Unknown
    confidence: int  # 0-100
    details: str
    category: str  # e.g., "SSH brute-force botnet", "Malware distribution"
    report_count: int


@dataclass(slots=True)
class ThreatIntelReport:
    results: list[ThreatIntelResult] = field(default_factory=list)

    @property
    def has_results(self) -> bool:
        return bool(self.results)

    @property
    def malicious_count(self) -> int:
        return sum(1 for r in self.results if r.reputation == "Malicious")

    @property
    def suspicious_count(self) -> int:
        return sum(1 for r in self.results if r.reputation == "Suspicious")


def _safe_http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> dict | None:
    """Perform a safe HTTP GET request and return parsed JSON or None."""
    req = urllib.request.Request(url, method="GET")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None


class ThreatIntelligence:
    """Checks indicators against public threat intelligence feeds.

    Supports:
    - AbuseIPDB (requires API key via ABUSEIPDB_API_KEY env var)
    - VirusTotal (requires API key via VIRUSTOTAL_API_KEY env var)
    - AlienVault OTX (free, no key required for basic lookups)
    """

    def __init__(self) -> None:
        import os
        self._abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        self._virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    def check_ip(self, ip: str) -> list[ThreatIntelResult]:
        """Check an IP address against all available threat feeds."""
        results: list[ThreatIntelResult] = []

        if self._abuseipdb_key:
            result = self._check_abuseipdb(ip)
            if result:
                results.append(result)

        if self._virustotal_key:
            result = self._check_virustotal_ip(ip)
            if result:
                results.append(result)

        # AlienVault OTX — free, no key required
        result = self._check_otx_ip(ip)
        if result:
            results.append(result)

        return results

    def check_domain(self, domain: str) -> list[ThreatIntelResult]:
        """Check a domain against available threat feeds."""
        results: list[ThreatIntelResult] = []

        if self._virustotal_key:
            result = self._check_virustotal_domain(domain)
            if result:
                results.append(result)

        result = self._check_otx_domain(domain)
        if result:
            results.append(result)

        return results

    def check_indicators(self, ips: list[str], domains: list[str]) -> ThreatIntelReport:
        """Check multiple IPs and domains and return a consolidated report."""
        report = ThreatIntelReport()

        for ip in ips[:10]:  # Limit to avoid rate limiting
            report.results.extend(self.check_ip(ip))

        for domain in domains[:10]:
            report.results.extend(self.check_domain(domain))

        # Sort by confidence descending
        report.results.sort(key=lambda r: r.confidence, reverse=True)
        return report

    # ------------------------------------------------------------------ #
    # AbuseIPDB                                                            #
    # ------------------------------------------------------------------ #

    def _check_abuseipdb(self, ip: str) -> ThreatIntelResult | None:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            "Key": self._abuseipdb_key,
            "Accept": "application/json",
        }
        data = _safe_http_get(url, headers=headers)
        if not data or "data" not in data:
            return None

        info = data["data"]
        score = info.get("abuseConfidenceScore", 0)
        total_reports = info.get("totalReports", 0)
        usage_type = info.get("usageType", "Unknown")
        isp = info.get("isp", "Unknown")
        country = info.get("countryCode", "??")

        if score >= 75:
            reputation = "Malicious"
        elif score >= 25:
            reputation = "Suspicious"
        else:
            reputation = "Clean"

        category = f"{usage_type} ({isp}, {country})"
        details = (
            f"Abuse confidence score: {score}%, "
            f"Total reports: {total_reports}, "
            f"ISP: {isp}, Country: {country}"
        )

        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            source="AbuseIPDB",
            reputation=reputation,
            confidence=score,
            details=details,
            category=category,
            report_count=total_reports,
        )

    # ------------------------------------------------------------------ #
    # VirusTotal                                                           #
    # ------------------------------------------------------------------ #

    def _check_virustotal_ip(self, ip: str) -> ThreatIntelResult | None:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self._virustotal_key}
        data = _safe_http_get(url, headers=headers)
        if not data or "data" not in data:
            return None

        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        score = int(((malicious + suspicious) / max(total, 1)) * 100)
        if malicious >= 3:
            reputation = "Malicious"
        elif malicious >= 1 or suspicious >= 2:
            reputation = "Suspicious"
        else:
            reputation = "Clean"

        owner = attrs.get("as_owner", "Unknown")
        country = attrs.get("country", "??")
        details = (
            f"Malicious: {malicious}, Suspicious: {suspicious}, "
            f"Total engines: {total}, Owner: {owner}, Country: {country}"
        )

        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            source="VirusTotal",
            reputation=reputation,
            confidence=score,
            details=details,
            category=f"AS: {owner} ({country})",
            report_count=malicious + suspicious,
        )

    def _check_virustotal_domain(self, domain: str) -> ThreatIntelResult | None:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self._virustotal_key}
        data = _safe_http_get(url, headers=headers)
        if not data or "data" not in data:
            return None

        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        score = int(((malicious + suspicious) / max(total, 1)) * 100)
        if malicious >= 3:
            reputation = "Malicious"
        elif malicious >= 1 or suspicious >= 2:
            reputation = "Suspicious"
        else:
            reputation = "Clean"

        registrar = attrs.get("registrar", "Unknown")
        details = (
            f"Malicious: {malicious}, Suspicious: {suspicious}, "
            f"Total engines: {total}, Registrar: {registrar}"
        )

        return ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            source="VirusTotal",
            reputation=reputation,
            confidence=score,
            details=details,
            category=f"Registrar: {registrar}",
            report_count=malicious + suspicious,
        )

    # ------------------------------------------------------------------ #
    # AlienVault OTX (free, no key required)                               #
    # ------------------------------------------------------------------ #

    def _check_otx_ip(self, ip: str) -> ThreatIntelResult | None:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        data = _safe_http_get(url)
        if not data:
            return None

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        reputation_val = data.get("reputation", 0)
        country = data.get("country_code", "??")

        if pulse_count >= 5 or reputation_val < -2:
            reputation = "Malicious"
            confidence = min(90, 50 + pulse_count * 5)
        elif pulse_count >= 1:
            reputation = "Suspicious"
            confidence = min(70, 30 + pulse_count * 10)
        else:
            reputation = "Clean"
            confidence = 10

        # Extract tags for category
        tags: list[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:3]:
            tags.extend(pulse.get("tags", [])[:3])
        category = ", ".join(tags[:5]) if tags else "No tags"

        details = (
            f"OTX Pulses: {pulse_count}, "
            f"Reputation: {reputation_val}, "
            f"Country: {country}"
        )

        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            source="AlienVault OTX",
            reputation=reputation,
            confidence=confidence,
            details=details,
            category=category,
            report_count=pulse_count,
        )

    def _check_otx_domain(self, domain: str) -> ThreatIntelResult | None:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        data = _safe_http_get(url)
        if not data:
            return None

        pulse_count = data.get("pulse_info", {}).get("count", 0)

        if pulse_count >= 5:
            reputation = "Malicious"
            confidence = min(90, 50 + pulse_count * 5)
        elif pulse_count >= 1:
            reputation = "Suspicious"
            confidence = min(70, 30 + pulse_count * 10)
        else:
            reputation = "Clean"
            confidence = 10

        tags: list[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:3]:
            tags.extend(pulse.get("tags", [])[:3])
        category = ", ".join(tags[:5]) if tags else "No tags"

        details = f"OTX Pulses: {pulse_count}"

        return ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            source="AlienVault OTX",
            reputation=reputation,
            confidence=confidence,
            details=details,
            category=category,
            report_count=pulse_count,
        )


def format_threat_intel_report(report: ThreatIntelReport) -> str:
    """Format threat intelligence results for display or prompt injection."""
    if not report.has_results:
        return "No threat intelligence data available for extracted indicators."

    lines: list[str] = []
    for r in report.results:
        rep_style = {
            "Malicious": "!!! MALICIOUS",
            "Suspicious": "!! SUSPICIOUS",
            "Clean": "CLEAN",
            "Unknown": "? UNKNOWN",
        }.get(r.reputation, r.reputation)

        lines.append(
            f"{r.indicator_type.upper()}: {r.indicator}\n"
            f"  Source: {r.source}\n"
            f"  Reputation: {rep_style}\n"
            f"  Confidence: {r.confidence}%\n"
            f"  Reports: {r.report_count}\n"
            f"  Category: {r.category}\n"
            f"  Details: {r.details}"
        )

    summary = (
        f"Total lookups: {len(report.results)}, "
        f"Malicious: {report.malicious_count}, "
        f"Suspicious: {report.suspicious_count}"
    )

    return f"Threat Intelligence Summary: {summary}\n\n" + "\n\n".join(lines)
