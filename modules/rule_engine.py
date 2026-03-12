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
        22:    ("Possible public SSH exposure",        "HIGH",     "Inspect SSH configuration, network exposure, and auth controls."),
        21:    ("Possible FTP exposure",               "HIGH",     "Inspect FTP necessity, encryption, and anonymous access controls."),
        23:    ("Telnet exposure",                     "CRITICAL", "Inspect legacy remote administration exposure and replacement options."),
        25:    ("SMTP exposure",                       "MEDIUM",   "Inspect SMTP relay configuration and open relay risk."),
        53:    ("DNS service exposure",                "MEDIUM",   "Inspect DNS resolver exposure and recursion settings."),
        80:    ("HTTP (unencrypted) service",          "LOW",      "Inspect redirect to HTTPS and content served over HTTP."),
        111:   ("RPC portmapper exposure",             "HIGH",     "Inspect RPC exposure; often indicates NFS or other legacy services."),
        139:   ("NetBIOS exposure",                    "HIGH",     "Inspect legacy Windows networking protocols and exposure."),
        443:   ("HTTPS service detected",              "INFO",     "Inspect TLS version, cipher suites, and certificate validity."),
        445:   ("SMB / Samba exposure",                "CRITICAL", "Inspect SMB version, patch level, and public exposure."),
        3306:  ("Possible MySQL exposure",             "HIGH",     "Inspect MySQL bind address, firewall rules, and remote grants."),
        3389:  ("RDP exposure",                        "CRITICAL", "Inspect RDP patch level, NLA enforcement, and firewall restrictions."),
        5432:  ("Possible PostgreSQL exposure",        "HIGH",     "Inspect PostgreSQL bind settings, pg_hba rules, and network restrictions."),
        6379:  ("Possible Redis exposure",             "CRITICAL", "Inspect Redis bind settings, protected mode, ACLs, and TLS."),
        8080:  ("HTTP alternative port service",       "MEDIUM",   "Inspect service on 8080; ensure it is intentional and hardened."),
        8443:  ("HTTPS alternative port service",      "LOW",      "Inspect TLS configuration for service on 8443."),
        9200:  ("Possible Elasticsearch exposure",     "CRITICAL", "Inspect cluster exposure, auth, and data access controls."),
        27017: ("Possible MongoDB exposure",           "CRITICAL", "Inspect MongoDB auth, bind address, and firewall rules."),
    }

    def evaluate(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        findings.extend(self._detect_exposed_ports(raw_data))
        findings.extend(self._detect_failed_logins(raw_data))
        findings.extend(self._detect_web_enumeration(raw_data))
        findings.extend(self._detect_admin_paths(raw_data))
        findings.extend(self._detect_firewall_issues(raw_data))
        findings.extend(self._detect_weak_tls(raw_data))
        findings.extend(self._detect_missing_security_headers(raw_data))
        findings.extend(self._detect_container_exposure(raw_data))
        findings.extend(self._detect_sudo_misuse(raw_data))
        findings.extend(self._detect_world_writable(raw_data))
        findings.extend(self._detect_sensitive_service_versions(raw_data))
        return self._deduplicate(findings)

    # ------------------------------------------------------------------ #
    # Port exposure                                                        #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # Authentication                                                       #
    # ------------------------------------------------------------------ #

    def _detect_failed_logins(self, raw_data: str) -> list[RuleFinding]:
        failed_patterns = re.findall(
            r"Failed password|authentication failure|Invalid user|FAILED LOGIN|pam_unix.*failure",
            raw_data, re.IGNORECASE,
        )
        if len(failed_patterns) >= 5:
            return [
                RuleFinding(
                    title="Possible brute-force or credential stuffing activity",
                    severity="HIGH",
                    confidence="high",
                    rationale=f"Detected {len(failed_patterns)} failed authentication indicators in the provided evidence.",
                    recommended_inspection_area="Authentication logs, SSH settings, fail2ban, and rate-limiting controls",
                )
            ]
        return []

    # ------------------------------------------------------------------ #
    # Web                                                                  #
    # ------------------------------------------------------------------ #

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
        admin_pattern = re.compile(
            r"/(admin|administrator|manage|console|wp-admin|phpmyadmin|actuator|dashboard|panel|cpanel|webmin)\b",
            re.IGNORECASE,
        )
        if admin_pattern.search(raw_data):
            return [
                RuleFinding(
                    title="Possible administrative endpoint exposure",
                    severity="HIGH",
                    confidence="medium",
                    rationale="The evidence references admin-like endpoints that may be publicly reachable or actively probed.",
                    recommended_inspection_area="Administrative routes, access control policies, and external exposure",
                )
            ]
        return []

    def _detect_missing_security_headers(self, raw_data: str) -> list[RuleFinding]:
        required_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        missing = [h for h in required_headers if h.lower() not in raw_data.lower()]
        # Only flag if we appear to be looking at HTTP headers
        if "HTTP/" in raw_data and len(missing) >= 2:
            return [
                RuleFinding(
                    title="Missing HTTP security headers",
                    severity="MEDIUM",
                    confidence="high",
                    rationale=f"The following security headers appear absent from the HTTP response: {', '.join(missing)}.",
                    recommended_inspection_area="Web server configuration, nginx/apache headers, or reverse proxy settings",
                )
            ]
        return []

    # ------------------------------------------------------------------ #
    # TLS                                                                  #
    # ------------------------------------------------------------------ #

    def _detect_weak_tls(self, raw_data: str) -> list[RuleFinding]:
        weak_patterns = re.compile(
            r"\b(TLSv1\.0|TLSv1\.1|SSLv2|SSLv3|RC4|DES|3DES|NULL|EXPORT|MD5)\b",
            re.IGNORECASE,
        )
        matches = weak_patterns.findall(raw_data)
        if matches:
            unique = list(dict.fromkeys(m.upper() for m in matches))
            return [
                RuleFinding(
                    title="Weak or deprecated TLS/cipher configuration detected",
                    severity="HIGH",
                    confidence="high",
                    rationale=f"Deprecated or weak protocol/cipher identifiers detected: {', '.join(unique[:6])}.",
                    recommended_inspection_area="TLS configuration files, nginx/apache ssl settings, openssl cipher suite selection",
                )
            ]
        return []

    # ------------------------------------------------------------------ #
    # Firewall                                                             #
    # ------------------------------------------------------------------ #

    def _detect_firewall_issues(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if re.search(r"Status:\s*inactive", raw_data, re.IGNORECASE):
            findings.append(RuleFinding(
                title="Firewall appears inactive",
                severity="CRITICAL",
                confidence="high",
                rationale="UFW or a firewall was detected with an inactive status.",
                recommended_inspection_area="ufw enable, iptables rules, nftables configuration",
            ))
        if re.search(r"Chain INPUT.*policy ACCEPT", raw_data, re.IGNORECASE):
            findings.append(RuleFinding(
                title="iptables default INPUT policy is ACCEPT",
                severity="HIGH",
                confidence="high",
                rationale="A default ACCEPT policy on INPUT allows all inbound traffic not explicitly blocked.",
                recommended_inspection_area="iptables -P INPUT DROP and explicit allow rules",
            ))
        return findings

    # ------------------------------------------------------------------ #
    # Container / Docker                                                   #
    # ------------------------------------------------------------------ #

    def _detect_container_exposure(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if re.search(r"0\.0\.0\.0:\d+->", raw_data):
            findings.append(RuleFinding(
                title="Docker container port bound to all interfaces",
                severity="HIGH",
                confidence="high",
                rationale="A Docker container is exposing a port on 0.0.0.0, making it reachable on all network interfaces.",
                recommended_inspection_area="Docker run -p or compose port binding; consider binding to 127.0.0.1",
            ))
        if re.search(r"privileged.*true|--privileged", raw_data, re.IGNORECASE):
            findings.append(RuleFinding(
                title="Docker container running in privileged mode",
                severity="CRITICAL",
                confidence="high",
                rationale="Privileged containers have near-full host access and can escape container isolation.",
                recommended_inspection_area="Remove --privileged and apply minimal capabilities via --cap-add",
            ))
        return findings

    # ------------------------------------------------------------------ #
    # System hardening                                                     #
    # ------------------------------------------------------------------ #

    def _detect_sudo_misuse(self, raw_data: str) -> list[RuleFinding]:
        if re.search(r"ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL", raw_data):
            return [RuleFinding(
                title="Unrestricted passwordless sudo detected",
                severity="CRITICAL",
                confidence="high",
                rationale="A sudoers entry grants full passwordless root access, eliminating privilege separation.",
                recommended_inspection_area="/etc/sudoers, /etc/sudoers.d/ — scope sudo grants to required commands only",
            )]
        return []

    def _detect_world_writable(self, raw_data: str) -> list[RuleFinding]:
        if re.search(r"-rwxrwxrwx|777|world.writable", raw_data, re.IGNORECASE):
            return [RuleFinding(
                title="World-writable files or directories detected",
                severity="HIGH",
                confidence="medium",
                rationale="Files or directories with world-write permissions allow any local user to modify them.",
                recommended_inspection_area="chmod, umask, and file permission audit — remove world-write where not required",
            )]
        return []

    def _detect_sensitive_service_versions(self, raw_data: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        old_ssh = re.search(r"OpenSSH[_ ]([0-9]+\.[0-9]+)", raw_data)
        if old_ssh:
            try:
                major, minor = old_ssh.group(1).split(".")
                if int(major) < 8:
                    findings.append(RuleFinding(
                        title="Outdated OpenSSH version detected",
                        severity="HIGH",
                        confidence="high",
                        rationale=f"OpenSSH {old_ssh.group(1)} is below the recommended minimum of 8.x and may contain known vulnerabilities.",
                        recommended_inspection_area="Update OpenSSH via package manager; review sshd_config hardening",
                    ))
            except (ValueError, AttributeError):
                pass
        if re.search(r"Apache/2\.[0-3]\.|nginx/1\.[0-9]\.", raw_data):
            findings.append(RuleFinding(
                title="Potentially outdated web server version in banner",
                severity="MEDIUM",
                confidence="medium",
                rationale="Web server version string suggests an older release. Banners also leak version information to attackers.",
                recommended_inspection_area="Update web server and suppress version banners with ServerTokens Prod / server_tokens off",
            ))
        return findings

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

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

