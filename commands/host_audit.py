"""Host audit command — comprehensive local Linux host security inspection."""

from __future__ import annotations

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import is_linux_like, linux_only_message
from modules.tool_runner import ToolRunner


def run_host_audit(system_prompt: str) -> AnalysisResult:
    """
    Run a comprehensive local host security audit.

    Collects listening services, firewall status, running processes,
    SSH configuration, container activity, disk/memory utilisation,
    recent log warnings, and kernel info, then feeds everything to the
    intelligence pipeline for a consolidated analyst report.
    """
    if not is_linux_like():
        return AnalysisResult(
            report=linux_only_message("host-audit"),
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    formatter = OutputFormatter()
    sections: list[str] = []

    formatter.print_info("[Host Audit] Starting comprehensive host inspection...")
    formatter.print_info("[Host Audit] Some commands may require sudo for full output.")

    # --- 1. Listening services ---
    if ToolRunner.is_installed("ss"):
        formatter.print_info("[Host Audit] Listening services (ss)...")
        stdout, _, _ = ToolRunner.run(["ss", "-tulpn"], timeout=30)
        if stdout.strip():
            sections.append("=== LISTENING SERVICES (ss -tulpn) ===\n" + stdout.strip())
    elif ToolRunner.is_installed("netstat"):
        formatter.print_info("[Host Audit] Listening services (netstat)...")
        stdout, _, _ = ToolRunner.run(["netstat", "-tulpn"], timeout=30)
        if stdout.strip():
            sections.append("=== LISTENING SERVICES (netstat -tulpn) ===\n" + stdout.strip())

    # --- 2. All established connections ---
    if ToolRunner.is_installed("ss"):
        stdout, _, _ = ToolRunner.run(["ss", "-tanp", "--no-header"], timeout=30)
        if stdout.strip():
            sections.append("=== ESTABLISHED CONNECTIONS (ss -tanp) ===\n" + stdout.strip())

    # --- 3. Firewall: ufw ---
    if ToolRunner.is_installed("ufw"):
        formatter.print_info("[Host Audit] Firewall status (ufw)...")
        stdout, _, _ = ToolRunner.run(["ufw", "status", "verbose"], timeout=20)
        if stdout.strip():
            sections.append("=== FIREWALL STATUS (ufw status verbose) ===\n" + stdout.strip())

    # --- 4. Firewall: iptables ---
    if ToolRunner.is_installed("iptables"):
        formatter.print_info("[Host Audit] Firewall rules (iptables)...")
        stdout, _, _ = ToolRunner.run_with_sudo(["iptables", "-S"], timeout=20)
        if stdout.strip():
            sections.append("=== IPTABLES RULES (iptables -S) ===\n" + stdout.strip())

    # --- 5. Firewall: nftables ---
    if ToolRunner.is_installed("nft"):
        stdout, _, _ = ToolRunner.run_with_sudo(["nft", "list", "ruleset"], timeout=20)
        if stdout.strip():
            sections.append("=== NFTABLES RULESET (nft list ruleset) ===\n" + stdout.strip())

    # --- 6. Running services ---
    if ToolRunner.is_installed("systemctl"):
        formatter.print_info("[Host Audit] Running systemd services...")
        stdout, _, _ = ToolRunner.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            timeout=30,
        )
        if stdout.strip():
            sections.append("=== RUNNING SERVICES (systemctl) ===\n" + stdout.strip())

        # Failed services — early warning
        stdout2, _, _ = ToolRunner.run(
            ["systemctl", "list-units", "--type=service", "--state=failed", "--no-pager"],
            timeout=20,
        )
        if stdout2.strip():
            sections.append("=== FAILED SERVICES (systemctl) ===\n" + stdout2.strip())

    # --- 7. fail2ban ---
    if ToolRunner.is_installed("fail2ban-client"):
        formatter.print_info("[Host Audit] fail2ban status...")
        stdout, _, _ = ToolRunner.run_with_sudo(["fail2ban-client", "status"], timeout=20)
        if stdout.strip():
            sections.append("=== FAIL2BAN STATUS ===\n" + stdout.strip())

    # --- 8. Recent warnings from journalctl ---
    if ToolRunner.is_installed("journalctl"):
        formatter.print_info("[Host Audit] Recent journal warnings and errors...")
        stdout, _, _ = ToolRunner.run(
            ["journalctl", "-n", "80", "--no-pager", "-p", "warning"],
            timeout=30,
        )
        if stdout.strip():
            sections.append("=== RECENT JOURNAL WARNINGS (journalctl -p warning -n 80) ===\n" + stdout.strip())

    # --- 9. SSH configuration ---
    sshd_config_path = "/etc/ssh/sshd_config"
    stdout2, _, rc2 = ToolRunner.run(["cat", sshd_config_path], timeout=10)
    if rc2 == 0 and stdout2.strip():
        formatter.print_info("[Host Audit] Reading sshd_config...")
        # Strip comment-only lines and blanks for brevity but keep all directives
        config_lines = [
            line for line in stdout2.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        sections.append(
            f"=== SSH DAEMON CONFIGURATION ({sshd_config_path}) ===\n"
            + "\n".join(config_lines)
        )

    # --- 10. Process snapshot (top CPU consumers, root processes) ---
    if ToolRunner.is_installed("ps"):
        formatter.print_info("[Host Audit] Process snapshot...")
        stdout, _, _ = ToolRunner.run(
            ["ps", "aux", "--sort=-%cpu"],
            timeout=20,
        )
        if stdout.strip():
            # Limit to 30 lines to avoid overwhelming analysis
            lines = stdout.strip().splitlines()[:30]
            sections.append("=== TOP PROCESSES BY CPU (ps aux --sort=-%cpu) ===\n" + "\n".join(lines))

    # --- 11. Disk usage ---
    if ToolRunner.is_installed("df"):
        stdout, _, _ = ToolRunner.run(["df", "-h"], timeout=15)
        if stdout.strip():
            sections.append("=== DISK USAGE (df -h) ===\n" + stdout.strip())

    # --- 12. Memory usage ---
    if ToolRunner.is_installed("free"):
        stdout, _, _ = ToolRunner.run(["free", "-h"], timeout=10)
        if stdout.strip():
            sections.append("=== MEMORY USAGE (free -h) ===\n" + stdout.strip())

    # --- 13. Uptime and load ---
    if ToolRunner.is_installed("uptime"):
        stdout, _, _ = ToolRunner.run(["uptime"], timeout=10)
        if stdout.strip():
            sections.append("=== UPTIME AND LOAD ===\n" + stdout.strip())

    # --- 14. Kernel / OS information ---
    if ToolRunner.is_installed("uname"):
        stdout, _, _ = ToolRunner.run(["uname", "-a"], timeout=10)
        if stdout.strip():
            sections.append("=== KERNEL VERSION (uname -a) ===\n" + stdout.strip())

    # --- 15. Docker containers ---
    if ToolRunner.is_installed("docker"):
        formatter.print_info("[Host Audit] Docker containers...")
        stdout, _, _ = ToolRunner.run_with_sudo(["docker", "ps", "--no-trunc"], timeout=30)
        if stdout.strip():
            sections.append("=== RUNNING CONTAINERS (docker ps) ===\n" + stdout.strip())
        # Also check for containers with privileged flag
        stdout2, _, _ = ToolRunner.run_with_sudo(
            ["docker", "inspect", "--format", "{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}}",
             "$(docker ps -q)"],
            timeout=20,
        )
        if stdout2.strip():
            sections.append("=== CONTAINER SECURITY FLAGS ===\n" + stdout2.strip())

    # --- 16. World-writable files in /etc ---
    formatter.print_info("[Host Audit] World-writable /etc files...")
    stdout, _, _ = ToolRunner.run_with_sudo(
        ["find", "/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
        timeout=30,
    )
    if stdout.strip():
        sections.append("=== WORLD-WRITABLE FILES IN /etc ===\n" + stdout.strip())
    else:
        sections.append("=== WORLD-WRITABLE FILES IN /etc ===\nNone found (good)")

    # --- 17. SUID/SGID binaries (high-risk) ---
    formatter.print_info("[Host Audit] SUID/SGID binaries...")
    stdout, _, _ = ToolRunner.run(
        ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "/6000", "-type", "f"],
        timeout=30,
    )
    if stdout.strip():
        sections.append("=== SUID/SGID BINARIES ===\n" + stdout.strip())

    if not sections:
        return AnalysisResult(
            report="[!] Host audit collected no data. Ensure basic tools (ss, systemctl, ps) are available.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    raw_evidence = "\n\n".join(sections)

    return run_intelligence_analysis(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        command_name="host-audit",
        target="localhost",
        task_instruction=(
            "This is a comprehensive local host security audit. "
            "Assess the complete security posture of this host: "
            "(1) Firewall effectiveness — detect default ACCEPT policies, missing rules, and services exposed with no protection; "
            "(2) Service exposure — identify services listening on 0.0.0.0 that should be restricted to localhost or LAN; "
            "(3) SSH hardening — check for PermitRootLogin yes, PasswordAuthentication yes, weak ciphers in sshd_config; "
            "(4) Container risks — flag Docker ports published to 0.0.0.0, privileged containers; "
            "(5) Brute-force protection — confirm fail2ban is active and jails cover SSH and web services; "
            "(6) Resource health — flag disk >85%, memory pressure, high load; "
            "(7) Process risks — identify unexpected root processes or high-CPU anomalies; "
            "(8) SUID/SGID risk — evaluate unusually privileged binaries. "
            "Assign combined severity and provide a prioritized step-by-step remediation plan."
        ),
    )
