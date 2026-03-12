"""Ports command — lists open ports/services and sends them for AI analysis."""

from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_ports(system_prompt: str) -> str:
    """
    List open ports/services with ss and return AI analysis.
    
    Args:
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of open ports
    """
    formatter = OutputFormatter()

    # Try ss first (preferred), fall back to netstat
    if ToolRunner.is_installed("ss"):
        stdout, stderr, returncode = ToolRunner.run(
            ["ss", "-tulpn"],
            timeout=30,
        )
    elif ToolRunner.is_installed("netstat"):
        stdout, stderr, returncode = ToolRunner.run(
            ["netstat", "-tulpn"],
            timeout=30,
        )
    else:
        return (
            "[!] Neither 'ss' nor 'netstat' found.\n"
            "    Install with: sudo apt install iproute2 (or net-tools)\n"
            "    Note: 'ss' is recommended on modern Linux systems."
        )

    output = stdout
    if returncode != 0 and stderr:
        output += f"\n[stderr]\n{stderr}"

    if not output.strip():
        return (
            "[!] No output from port listing.\n"
            "    You may need to run Freddy with sudo: sudo python3 freddy.py ports"
        )

    # Send to AI for analysis
    return analyze(output, system_prompt)
