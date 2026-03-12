"""Audit command — runs a combined local system security audit."""

from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_audit(system_prompt: str) -> str:
    """
    Run a combined local system security audit.
    
    Args:
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the system audit
    """
    formatter = OutputFormatter()
    audit_data = []

    formatter.print_info("Running system security audit...")
    formatter.print_info("(Some commands may require sudo)")

    # 1. List open ports
    if ToolRunner.is_installed("ss"):
        formatter.print_info("Checking open ports (ss)...")
        stdout, _, _ = ToolRunner.run(["ss", "-tulpn"], timeout=30)
        if stdout.strip():
            audit_data.append("=== OPEN PORTS (ss -tulpn) ===\n" + stdout)
    elif ToolRunner.is_installed("netstat"):
        formatter.print_info("Checking open ports (netstat)...")
        stdout, _, _ = ToolRunner.run(["netstat", "-tulpn"], timeout=30)
        if stdout.strip():
            audit_data.append("=== OPEN PORTS (netstat -tulpn) ===\n" + stdout)

    # 2. List running services
    if ToolRunner.is_installed("systemctl"):
        formatter.print_info("Checking running services...")
        stdout, _, _ = ToolRunner.run(
            ["systemctl", "list-units", "--type=service", "--state=running"],
            timeout=30,
        )
        if stdout.strip():
            audit_data.append("=== RUNNING SERVICES ===\n" + stdout)

    # 3. Firewall status
    if ToolRunner.is_installed("ufw"):
        formatter.print_info("Checking firewall (ufw)...")
        stdout, _, _ = ToolRunner.run_with_sudo(["ufw", "status"], timeout=30)
        if stdout.strip() and not "ERROR" in stdout:
            audit_data.append("=== UFW FIREWALL STATUS ===\n" + stdout)

    # 4. iptables rules
    if ToolRunner.is_installed("iptables"):
        formatter.print_info("Checking firewall rules (iptables)...")
        stdout, _, _ = ToolRunner.run_with_sudo(["iptables", "-L", "-n"], timeout=30)
        if stdout.strip() and not "ERROR" in stdout:
            audit_data.append("=== IPTABLES RULES ===\n" + stdout)

    # 5. System info
    if ToolRunner.is_installed("uname"):
        formatter.print_info("Gathering system information...")
        stdout, _, _ = ToolRunner.run(["uname", "-a"], timeout=10)
        if stdout.strip():
            audit_data.append("=== SYSTEM INFORMATION ===\n" + stdout)

    # 6. Users and groups
    formatter.print_info("Checking users with login shells...")
    stdout, _, _ = ToolRunner.run_shell(
        "cat /etc/passwd | grep '/bin/bash\\|/bin/sh' | cut -d: -f1,3",
        timeout=10,
    )
    if stdout.strip():
        audit_data.append("=== USERS WITH LOGIN SHELLS ===\n" + stdout)

    # Combine all audit data
    combined_output = "\n".join(audit_data)

    if not combined_output.strip():
        return (
            "[!] Audit produced no output.\n"
            "    Some commands may require elevated privileges.\n"
            "    Try: sudo python3 freddy.py audit"
        )

    # Send to AI for analysis
    return analyze(combined_output, system_prompt)
