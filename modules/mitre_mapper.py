"""MITRE ATT&CK Mapper — maps detected behaviors to real attack techniques."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    evidence_summary: str
    confidence: str  # HIGH, MEDIUM, LOW


# Comprehensive MITRE ATT&CK technique database for defensive mapping
TECHNIQUE_DB: list[dict] = [
    # Credential Access
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "patterns": [
            r"[Ff]ailed\s+password",
            r"authentication\s+failure",
            r"[Ii]nvalid\s+user",
            r"FAILED\s+LOGIN",
            r"pam_unix.*failure",
            r"brute.?force",
            r"repeated.*login.*fail",
        ],
        "threshold": 3,
    },
    {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "patterns": [
            r"Failed password for .+ from .+ port \d+",
        ],
        "threshold": 5,
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "patterns": [
            r"Failed password for (different|multiple|various) user",
            r"Invalid user \w+ from",
        ],
        "threshold": 5,
    },
    {
        "id": "T1110.004",
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "patterns": [
            r"credential.?stuff",
            r"automated.*login.*attempt",
        ],
        "threshold": 1,
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "patterns": [
            r"password.*plain.?text",
            r"credentials?\s+in\s+file",
            r"\.env\b.*password",
            r"hardcoded.*password",
            r"default.*credential",
        ],
        "threshold": 1,
    },
    # Initial Access
    {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "patterns": [
            r"22/(tcp|udp)\s+open",
            r"3389/(tcp|udp)\s+open",
            r"23/(tcp|udp)\s+open",
            r"ssh.*open",
            r"rdp.*open",
            r"telnet.*open",
            r"vnc.*open",
            r"5900/(tcp|udp)\s+open",
        ],
        "threshold": 1,
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "patterns": [
            r"CVE-\d{4}-\d+",
            r"exploit",
            r"remote\s+code\s+execution",
            r"RCE",
            r"SQL\s*injection",
            r"command\s+injection",
            r"buffer\s+overflow",
        ],
        "threshold": 1,
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "patterns": [
            r"Accepted\s+(password|publickey)\s+for\s+root",
            r"session\s+opened\s+for\s+user\s+root",
            r"root\s+login",
        ],
        "threshold": 1,
    },
    {
        "id": "T1078.003",
        "name": "Valid Accounts: Local Accounts",
        "tactic": "Privilege Escalation",
        "patterns": [
            r"Accepted.*for root from",
            r"pam_unix.*session opened.*root",
        ],
        "threshold": 1,
    },
    # Discovery
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "patterns": [
            r"Nmap\s+scan\s+report",
            r"port\s+scan",
            r"SYN\s+scan",
            r"banner\s+grab",
            r"service\s+detection",
            r"masscan",
            r"zmap",
        ],
        "threshold": 1,
    },
    {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "patterns": [
            r"host\s+discovery",
            r"ping\s+sweep",
            r"ARP\s+scan",
            r"network.*scan",
        ],
        "threshold": 1,
    },
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "patterns": [
            r"nmap",
            r"nikto",
            r"gobuster",
            r"dirb",
            r"wfuzz",
            r"ffuf",
            r"nuclei",
        ],
        "threshold": 1,
    },
    # Persistence
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "patterns": [
            r"useradd",
            r"adduser",
            r"new\s+user.*created",
            r"account\s+created",
        ],
        "threshold": 1,
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "patterns": [
            r"crontab",
            r"cron\s*job",
            r"/etc/cron",
            r"at\s+command",
            r"systemd.*timer",
        ],
        "threshold": 1,
    },
    {
        "id": "T1543",
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "patterns": [
            r"systemctl.*enable",
            r"service.*start",
            r"init\.d",
            r"rc\.local",
            r"systemd.*service\s+file",
        ],
        "threshold": 1,
    },
    # Privilege Escalation
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "patterns": [
            r"NOPASSWD.*ALL",
            r"sudo.*root",
            r"SUID",
            r"setuid",
            r"privilege.*escalat",
            r"chmod\s+[us]\+s",
        ],
        "threshold": 1,
    },
    # Defense Evasion
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "patterns": [
            r"firewall.*disabled",
            r"ufw.*inactive",
            r"iptables.*ACCEPT.*default",
            r"selinux.*disabled",
            r"apparmor.*disabled",
            r"antivirus.*disabled",
        ],
        "threshold": 1,
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "patterns": [
            r"log.*clear",
            r"log.*delet",
            r"log.*rotat.*force",
            r"history.*clear",
            r"bash_history.*delet",
            r"/var/log.*truncat",
        ],
        "threshold": 1,
    },
    # Lateral Movement
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "patterns": [
            r"ssh.*from\s+\d+\.\d+\.\d+\.\d+",
            r"rdp.*connect",
            r"lateral.*mov",
            r"pivot",
        ],
        "threshold": 1,
    },
    # Exfiltration
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "patterns": [
            r"dns.*tunnel",
            r"icmp.*tunnel",
            r"exfiltrat",
            r"data.*leak",
        ],
        "threshold": 1,
    },
    # Execution
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "patterns": [
            r"/tmp/.*\.(sh|py|pl|rb)",
            r"wget.*\|.*sh",
            r"curl.*\|.*bash",
            r"reverse.*shell",
            r"bind.*shell",
            r"web.?shell",
        ],
        "threshold": 1,
    },
    # Collection
    {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "patterns": [
            r"/etc/passwd",
            r"/etc/shadow",
            r"\.ssh/.*key",
            r"sensitive.*file.*access",
        ],
        "threshold": 1,
    },
    # Impact
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "patterns": [
            r"denial.of.service",
            r"DoS\b",
            r"DDoS",
            r"resource\s+exhaust",
            r"syn\s+flood",
        ],
        "threshold": 1,
    },
    # Web Application Attacks
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "patterns": [
            r"/(admin|wp-admin|phpmyadmin|console|actuator|dashboard|panel)",
            r"directory.*travers",
            r"path.*travers",
            r"\.\.(/|\\)",
            r"\bLFI\b",
            r"\bRFI\b",
            r"file\s+inclus",
        ],
        "threshold": 1,
    },
    {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "patterns": [
            r"\b(401|403|404)\b.*\b(401|403|404)\b",
            r"web\s+enum",
            r"forced?\s+brows",
            r"directory.*bust",
        ],
        "threshold": 1,
    },
    # Network
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "patterns": [
            r"C2\b",
            r"command.*control",
            r"beacon",
            r"callback",
            r"reverse.*connect",
        ],
        "threshold": 1,
    },
    # Weak Crypto
    {
        "id": "T1573",
        "name": "Encrypted Channel (Weak)",
        "tactic": "Command and Control",
        "patterns": [
            r"SSLv[23]",
            r"TLSv1\.0",
            r"TLSv1\.1",
            r"RC4",
            r"DES\b",
            r"3DES",
            r"NULL.*cipher",
            r"EXPORT.*cipher",
            r"weak.*cipher",
            r"weak.*tls",
        ],
        "threshold": 1,
    },
]


class MitreMapper:
    """Maps evidence and rule findings to MITRE ATT&CK techniques."""

    def map_evidence(self, raw_evidence: str, rule_titles: list[str] | None = None) -> list[MitreMapping]:
        """Scan raw evidence for MITRE ATT&CK technique indicators."""
        mappings: list[MitreMapping] = []
        seen_ids: set[str] = set()

        combined_text = raw_evidence
        if rule_titles:
            combined_text += "\n" + "\n".join(rule_titles)

        for technique in TECHNIQUE_DB:
            if technique["id"] in seen_ids:
                continue
            match_count = 0
            matched_snippets: list[str] = []
            for pattern in technique["patterns"]:
                hits = re.findall(pattern, combined_text, re.IGNORECASE | re.MULTILINE)
                match_count += len(hits)
                if hits:
                    # Capture up to 3 example matches for evidence summary
                    for hit in hits[:3]:
                        snippet = hit if isinstance(hit, str) else str(hit)
                        if snippet and snippet not in matched_snippets:
                            matched_snippets.append(snippet)

            if match_count >= technique["threshold"]:
                confidence = "HIGH" if match_count >= 5 else ("MEDIUM" if match_count >= 2 else "LOW")
                evidence_text = (
                    f"{match_count} indicator(s) detected"
                )
                if matched_snippets:
                    evidence_text += f": {', '.join(matched_snippets[:3])}"

                mappings.append(MitreMapping(
                    technique_id=technique["id"],
                    technique_name=technique["name"],
                    tactic=technique["tactic"],
                    evidence_summary=evidence_text,
                    confidence=confidence,
                ))
                seen_ids.add(technique["id"])

        # Sort by confidence then technique ID
        priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        mappings.sort(key=lambda m: (priority.get(m.confidence, 3), m.technique_id))
        return mappings


def format_mitre_mappings(mappings: list[MitreMapping]) -> str:
    """Format MITRE ATT&CK mappings for inclusion in AI prompt context."""
    if not mappings:
        return "No MITRE ATT&CK technique mappings identified."
    lines: list[str] = []
    for m in mappings:
        lines.append(
            f"[{m.confidence}] {m.technique_id} — {m.technique_name}\n"
            f"  Tactic: {m.tactic}\n"
            f"  Evidence: {m.evidence_summary}"
        )
    return "\n\n".join(lines)
