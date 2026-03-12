"""Scan command — runs Nmap service detection against a target."""

import shlex
from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_scan(target: str, system_prompt: str) -> str:
    """
    Run an Nmap service version scan on the target and return AI analysis.
    
    Args:
        target: Target host or IP address
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the scan results
    """
    formatter = OutputFormatter()

    # Verify nmap is installed
    if not ToolRunner.is_installed("nmap"):
        return (
            "[!] Nmap is not installed.\n"
            "    Install it with:  sudo apt install nmap\n"
            "    (Available in Kali Linux by default)"
        )

    # Sanitize target
    safe_target = shlex.quote(target)

    # Run nmap scan
    stdout, stderr, returncode = ToolRunner.run(
        ["nmap", "-sV", safe_target],
        timeout=300,
    )

    output = stdout
    if returncode != 0 and stderr:
        output += f"\n[stderr]\n{stderr}"

    if not output.strip():
        return (
            "[!] Nmap produced no output.\n"
            "    Check that the target is reachable and spelled correctly."
        )

    # Send to AI for analysis
    return analyze(output, system_prompt)
