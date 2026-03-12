"""WHOIS lookup command — queries domain WHOIS information."""

import shlex
from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_whois(domain: str, system_prompt: str) -> str:
    """
    Query WHOIS information for a domain.
    
    Args:
        domain: Domain to query
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of WHOIS information
    """
    formatter = OutputFormatter()

    # Verify whois is installed
    if not ToolRunner.is_installed("whois"):
        return (
            "[!] Whois is not installed.\n"
            "    Install it with: sudo apt install whois"
        )

    safe_domain = shlex.quote(domain)

    formatter.print_info(f"Querying WHOIS for {domain}...")

    stdout, stderr, returncode = ToolRunner.run(["whois", safe_domain], timeout=60)

    output = stdout if stdout.strip() else ""
    if not output.strip() and stderr:
        output = stderr

    if not output.strip():
        return (
            "[!] No WHOIS data obtained.\n"
            "    Check that the domain is valid and the whois server is accessible."
        )

    # Send to AI for analysis
    return analyze(output, system_prompt)
