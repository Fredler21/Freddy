"""Audit command — runs a combined local system security audit."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import is_linux_like, linux_only_message
from modules.tool_runner import ToolRunner


def run_audit(system_prompt: str) -> AnalysisResult:
    """
    Run a combined local system security audit.
    
    Args:
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the system audit
    """
    if not is_linux_like():
        return AnalysisResult(
            report=linux_only_message("audit"),
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

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
        return AnalysisResult(
            report="[!] Audit produced no output. Some commands may require elevated privileges.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=combined_output,
        system_prompt=system_prompt,
        command_name="audit",
        target="local",
        task_instruction="Perform a defensive host audit using this combined system evidence. Identify exposure, weak controls, and remediation priorities.",
    )
