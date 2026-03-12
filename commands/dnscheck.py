"""DNS check command — analyzes DNS records and resolution."""

import shlex
from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_dnscheck(domain: str, system_prompt: str) -> str:
    """
    Check DNS records and resolution.
    
    Args:
        domain: Domain to check
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of DNS configuration
    """
    formatter = OutputFormatter()
    dns_data = []

    safe_domain = shlex.quote(domain)

    # 1. dig
    if ToolRunner.is_installed("dig"):
        formatter.print_info("Running dig...")
        stdout, _, _ = ToolRunner.run(["dig", safe_domain], timeout=30)
        if stdout.strip():
            dns_data.append("=== DIG OUTPUT ===\n" + stdout)

    # 2. nslookup  
    if ToolRunner.is_installed("nslookup"):
        formatter.print_info("Running nslookup...")
        stdout, _, _ = ToolRunner.run(["nslookup", safe_domain], timeout=30)
        if stdout.strip():
            dns_data.append("=== NSLOOKUP OUTPUT ===\n" + stdout)

    # 3. host
    if ToolRunner.is_installed("host"):
        formatter.print_info("Running host...")
        stdout, _, _ = ToolRunner.run(["host", safe_domain], timeout=30)
        if stdout.strip():
            dns_data.append("=== HOST OUTPUT ===\n" + stdout)

    combined_output = "\n".join(dns_data)

    if not combined_output.strip():
        return (
            "[!] DNS check produced no output.\n"
            "    Install DNS tools: dnsutils, bind-tools\n"
            "    sudo apt install dnsutils"
        )

    # Send to AI for analysis
    return analyze(combined_output, system_prompt)
