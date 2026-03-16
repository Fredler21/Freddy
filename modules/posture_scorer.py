"""Security Posture Scorer — calculates an overall security score for a target."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PostureIssue:
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    penalty: int  # Points deducted (0-25)
    category: str  # e.g., "Network", "Authentication", "Encryption", "Configuration"


@dataclass(slots=True)
class PostureScore:
    score: int  # 0-100
    grade: str  # A, B, C, D, F
    issues: list[PostureIssue] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.score >= 90:
            return "LOW"
        elif self.score >= 70:
            return "MEDIUM"
        elif self.score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"


# Penalty rules: (pattern_check_function_name, description, severity, penalty, category)
_SEVERITY_PENALTY = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}


class PostureScorer:
    """Calculates a security posture score based on detected issues."""

    def score(
        self,
        rule_findings: list | None = None,
        mitre_mappings: list | None = None,
        ioc_count: int = 0,
        correlation_findings: list | None = None,
        raw_evidence: str = "",
    ) -> PostureScore:
        """Calculate security posture score from all analysis outputs."""
        issues: list[PostureIssue] = []
        strengths: list[str] = []

        # Score from rule findings
        if rule_findings:
            for finding in rule_findings:
                severity = getattr(finding, "severity", "MEDIUM").upper()
                penalty = _SEVERITY_PENALTY.get(severity, 5)
                issues.append(PostureIssue(
                    description=getattr(finding, "title", str(finding)),
                    severity=severity,
                    penalty=penalty,
                    category=self._categorize_finding(getattr(finding, "title", "")),
                ))
        else:
            strengths.append("No deterministic security rule violations detected")

        # Score from MITRE ATT&CK mappings
        if mitre_mappings:
            for mapping in mitre_mappings:
                confidence = getattr(mapping, "confidence", "LOW")
                penalty = {"HIGH": 8, "MEDIUM": 5, "LOW": 2}.get(confidence, 2)
                issues.append(PostureIssue(
                    description=f"ATT&CK: {getattr(mapping, 'technique_id', '?')} — {getattr(mapping, 'technique_name', '?')}",
                    severity="HIGH" if confidence == "HIGH" else "MEDIUM",
                    penalty=penalty,
                    category="Threat Detection",
                ))
        else:
            strengths.append("No MITRE ATT&CK technique indicators detected")

        # IOC penalty
        if ioc_count > 0:
            ioc_penalty = min(15, ioc_count * 2)
            issues.append(PostureIssue(
                description=f"{ioc_count} Indicators of Compromise extracted",
                severity="HIGH" if ioc_count >= 5 else "MEDIUM",
                penalty=ioc_penalty,
                category="Threat Indicators",
            ))
        else:
            strengths.append("No external Indicators of Compromise detected")

        # Correlation findings penalty
        if correlation_findings:
            for cf in correlation_findings:
                severity = getattr(cf, "severity", "MEDIUM")
                penalty = _SEVERITY_PENALTY.get(severity, 5)
                issues.append(PostureIssue(
                    description=getattr(cf, "title", str(cf)),
                    severity=severity,
                    penalty=penalty,
                    category="Cross-Source Correlation",
                ))

        # Evidence-based checks
        evidence_checks = self._check_evidence_strengths(raw_evidence)
        strengths.extend(evidence_checks)

        # Calculate final score
        total_penalty = sum(i.penalty for i in issues)
        score = max(0, min(100, 100 - total_penalty))
        grade = self._calculate_grade(score)

        return PostureScore(
            score=score,
            grade=grade,
            issues=issues,
            strengths=strengths,
        )

    def _categorize_finding(self, title: str) -> str:
        """Categorize a finding by its description."""
        title_lower = title.lower()
        if any(w in title_lower for w in ("ssh", "ftp", "telnet", "rdp", "port", "smb", "service")):
            return "Network Exposure"
        if any(w in title_lower for w in ("tls", "ssl", "cipher", "certificate")):
            return "Encryption"
        if any(w in title_lower for w in ("login", "password", "brute", "auth", "credential")):
            return "Authentication"
        if any(w in title_lower for w in ("firewall", "ufw", "iptables")):
            return "Firewall"
        if any(w in title_lower for w in ("header", "csp", "hsts")):
            return "Web Security"
        if any(w in title_lower for w in ("sudo", "suid", "permission", "writable")):
            return "System Hardening"
        if any(w in title_lower for w in ("docker", "container", "privileged")):
            return "Container Security"
        return "Configuration"

    def _check_evidence_strengths(self, raw_evidence: str) -> list[str]:
        """Identify positive security indicators in evidence."""
        strengths: list[str] = []
        evidence_lower = raw_evidence.lower()

        if "strict-transport-security" in evidence_lower:
            strengths.append("HSTS header is present")
        if "content-security-policy" in evidence_lower:
            strengths.append("Content-Security-Policy header found")
        if "x-frame-options" in evidence_lower:
            strengths.append("X-Frame-Options header set")
        if "fail2ban" in evidence_lower and "active" in evidence_lower:
            strengths.append("fail2ban is active")
        if "ufw" in evidence_lower and "status: active" in evidence_lower:
            strengths.append("UFW firewall is active")
        if "pubkeyauthentication yes" in evidence_lower:
            strengths.append("SSH public key authentication is enabled")

        return strengths

    def _calculate_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


def format_posture_score(posture: PostureScore) -> str:
    """Format posture score for terminal display."""
    lines: list[str] = []

    # Score header
    bar_filled = posture.score // 5
    bar_empty = 20 - bar_filled
    bar = "█" * bar_filled + "░" * bar_empty
    lines.append(f"Security Posture Score: {posture.score} / 100  [{bar}]  Grade: {posture.grade}")
    lines.append(f"Risk Level: {posture.risk_level}")
    lines.append("")

    # Issues by category
    if posture.issues:
        lines.append("Issues Detected:")
        categories: dict[str, list[PostureIssue]] = {}
        for issue in posture.issues:
            categories.setdefault(issue.category, []).append(issue)

        for cat, cat_issues in sorted(categories.items()):
            lines.append(f"\n  [{cat}]")
            for issue in cat_issues:
                lines.append(f"    [{issue.severity}] {issue.description} (-{issue.penalty} pts)")

    # Strengths
    if posture.strengths:
        lines.append("\nStrengths:")
        for strength in posture.strengths:
            lines.append(f"  ✓ {strength}")

    return "\n".join(lines)
