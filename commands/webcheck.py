"""Web check command — analyzes web server security."""

import shlex
from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_webcheck(target: str, system_prompt: str) -> str:
    """
    Run web security checks on a target using available tools.
    
    Args:
        target: Target URL or domain
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of web server security
    """
    formatter = OutputFormatter()
    web_data = []

    safe_target = shlex.quote(target)

    # 1. whatweb
    if ToolRunner.is_installed("whatweb"):
        formatter.print_info("Running whatweb...")
        stdout, stderr, _ = ToolRunner.run(["whatweb", safe_target], timeout=60)
        if stdout.strip():
            web_data.append("=== WHATWEB OUTPUT ===\n" + stdout)
    else:
        formatter.print_warning("whatweb not installed")

    # 2. nikto
    if ToolRunner.is_installed("nikto"):
        formatter.print_info("Running nikto (this may take a while)...")
        stdout, stderr, _ = ToolRunner.run(
            ["nikto", "-h", safe_target], timeout=120
        )
        if stdout.strip():
            web_data.append("=== NIKTO OUTPUT ===\n" + stdout)
    else:
        formatter.print_warning("nikto not installed")

    # 3. curl for headers
    if ToolRunner.is_installed("curl"):
        formatter.print_info("Checking HTTP headers...")
        stdout, stderr, _ = ToolRunner.run(
            ["curl", "-I", "-s", safe_target],
            timeout=30,
        )
        if stdout.strip():
            web_data.append("=== HTTP HEADERS ===\n" + stdout)

    combined_output = "\n".join(web_data)

    if not combined_output.strip():
        return (
            "[!] Web check produced no output.\n"
            "    Install security tools: nikto, whatweb, curl\n"
            "    sudo apt install nikto whatweb curl"
        )

    # Send to AI for analysis
    return analyze(combined_output, system_prompt)
