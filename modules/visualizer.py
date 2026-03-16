"""Visualization Module — generates ASCII/text-based security visualizations."""

from __future__ import annotations

from collections import Counter


class SecurityVisualizer:
    """Generates text-based security visualizations for terminal display."""

    def attack_timeline_chart(self, timeline_events: list) -> str:
        """Generate an ASCII attack timeline chart."""
        if not timeline_events:
            return "No timeline events to visualize."

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│           ATTACK TIMELINE                   │")
        lines.append("├─────────────────────────────────────────────┤")

        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "⚪",
        }

        for event in timeline_events[:25]:
            ts = getattr(event, "timestamp", "?")
            event_type = getattr(event, "event_type", "?")
            severity = getattr(event, "severity", "INFO")
            source_ip = getattr(event, "source_ip", "")
            icon = severity_icons.get(severity, "⚪")

            ip_part = f" ← {source_ip}" if source_ip else ""
            line = f"│ {icon} {ts:<16} {event_type:<24}{ip_part}"
            lines.append(line[:70].ljust(46) + "│")

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def severity_distribution(self, rule_findings: list) -> str:
        """Generate a severity distribution bar chart."""
        if not rule_findings:
            return "No findings to visualize."

        severity_counts = Counter(
            getattr(f, "severity", "MEDIUM").upper() for f in rule_findings
        )

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         SEVERITY DISTRIBUTION               │")
        lines.append("├─────────────────────────────────────────────┤")

        max_count = max(severity_counts.values()) if severity_counts else 1
        bar_max = 25

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        colors = {
            "CRITICAL": "█",
            "HIGH": "▓",
            "MEDIUM": "▒",
            "LOW": "░",
            "INFO": "·",
        }

        for sev in severity_order:
            count = severity_counts.get(sev, 0)
            if count == 0:
                continue
            bar_len = max(1, int((count / max_count) * bar_max))
            bar = colors.get(sev, "█") * bar_len
            line = f"│ {sev:<10} {bar:<25} {count:>3} │"
            lines.append(line)

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def ip_activity_map(self, ioc_ips: list[str], raw_evidence: str = "") -> str:
        """Generate an IP activity summary visualization."""
        if not ioc_ips:
            return "No IP addresses to visualize."

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         SUSPICIOUS IP ACTIVITY MAP          │")
        lines.append("├─────────────────────────────────────────────┤")

        ip_counts = Counter()
        for ip in ioc_ips:
            ip_counts[ip] = raw_evidence.count(ip)

        for ip, count in ip_counts.most_common(15):
            bar_len = min(20, max(1, count))
            bar = "█" * bar_len
            line = f"│ {ip:<16} {bar:<20} ({count:>4}x) │"
            lines.append(line[:46] + "│")

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def attack_surface_map(self, open_ports: list[str]) -> str:
        """Generate an attack surface map from open ports."""
        if not open_ports:
            return "No open ports to visualize."

        # Service names for common ports
        service_names = {
            "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
            "53": "DNS", "80": "HTTP", "110": "POP3", "111": "RPC",
            "139": "NetBIOS", "143": "IMAP", "443": "HTTPS", "445": "SMB",
            "993": "IMAPS", "995": "POP3S", "3306": "MySQL", "3389": "RDP",
            "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis",
            "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "9200": "Elasticsearch",
            "27017": "MongoDB",
        }

        risk_level = {
            "21": "HIGH", "22": "HIGH", "23": "CRIT", "25": "MED",
            "53": "MED", "80": "LOW", "111": "HIGH", "139": "HIGH",
            "443": "INFO", "445": "CRIT", "3306": "HIGH", "3389": "CRIT",
            "5432": "HIGH", "6379": "CRIT", "9200": "CRIT", "27017": "CRIT",
        }

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         ATTACK SURFACE MAP                  │")
        lines.append("├─────────────────────────────────────────────┤")

        for port_entry in open_ports[:20]:
            port_num = port_entry.split("/")[0]
            proto = port_entry.split("/")[1] if "/" in port_entry else "tcp"
            svc = service_names.get(port_num, "Unknown")
            risk = risk_level.get(port_num, "INFO")

            risk_indicator = {"CRIT": "🔴", "HIGH": "🟠", "MED": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(risk, "⚪")
            line = f"│ {risk_indicator} Port {port_num:<6}/{proto:<4} → {svc:<14} [{risk}] │"
            lines.append(line[:46] + "│")

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def posture_gauge(self, score: int, grade: str) -> str:
        """Generate a visual security posture gauge."""
        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         SECURITY POSTURE GAUGE              │")
        lines.append("├─────────────────────────────────────────────┤")

        # Gauge bar
        filled = score // 5
        empty = 20 - filled
        if score >= 80:
            bar_char = "█"
        elif score >= 60:
            bar_char = "▓"
        elif score >= 40:
            bar_char = "▒"
        else:
            bar_char = "░"

        gauge = bar_char * filled + "·" * empty
        lines.append(f"│  [{gauge}] {score}/100    │")
        lines.append(f"│  Grade: {grade}                                  │"[:46] + "│")

        # Risk indicator
        if score >= 90:
            risk_text = "✅ LOW RISK — Strong security posture"
        elif score >= 70:
            risk_text = "⚠️  MEDIUM RISK — Improvements needed"
        elif score >= 50:
            risk_text = "🟠 HIGH RISK — Significant issues found"
        else:
            risk_text = "🔴 CRITICAL — Immediate action required"

        lines.append(f"│  {risk_text}"[:46] + "│")
        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def mitre_attack_matrix(self, mitre_mappings: list) -> str:
        """Generate a MITRE ATT&CK matrix visualization."""
        if not mitre_mappings:
            return "No MITRE ATT&CK techniques to visualize."

        # Group by tactic
        tactics: dict[str, list] = {}
        for m in mitre_mappings:
            tactic = getattr(m, "tactic", "Unknown")
            tactics.setdefault(tactic, []).append(m)

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         MITRE ATT&CK MATRIX                │")
        lines.append("├─────────────────────────────────────────────┤")

        conf_icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}

        for tactic, mappings in tactics.items():
            lines.append(f"│ ┌ {tactic:<41} │")
            for m in mappings:
                tid = getattr(m, "technique_id", "?")
                name = getattr(m, "technique_name", "?")
                conf = getattr(m, "confidence", "LOW")
                icon = conf_icons.get(conf, "⚪")
                technique_str = f"{tid} {name}"
                line = f"│ │ {icon} {technique_str:<38}"
                lines.append(line[:46] + "│")
            lines.append(f"│ └{'─' * 42}│")

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)

    def connection_graph(self, ioc_ips: list[str], target: str) -> str:
        """Generate a text-based connection graph."""
        if not ioc_ips:
            return "No connections to visualize."

        lines: list[str] = []
        lines.append("┌─────────────────────────────────────────────┐")
        lines.append("│         CONNECTION GRAPH                    │")
        lines.append("├─────────────────────────────────────────────┤")
        lines.append(f"│           ┌─────────────┐                  │")
        lines.append(f"│           │  {target[:11]:<11} │                  │")
        lines.append(f"│           └──────┬──────┘                  │")

        for i, ip in enumerate(ioc_ips[:8]):
            connector = "├" if i < len(ioc_ips[:8]) - 1 else "└"
            lines.append(f"│                  {connector}──── {ip:<15}    │")

        lines.append("└─────────────────────────────────────────────┘")
        return "\n".join(lines)
