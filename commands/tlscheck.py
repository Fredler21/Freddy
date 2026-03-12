"""TLS check command — analyzes TLS/SSL certificate and configuration."""

import shlex
from modules.tool_runner import ToolRunner
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_tlscheck(target: str, system_prompt: str) -> str:
    """
    Check TLS/SSL certificate and configuration.
    
    Args:
        target: Target host (e.g., example.com, example.com:8443)
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of TLS/SSL configuration
    """
    formatter = OutputFormatter()

    # Verify openssl is installed
    if not ToolRunner.is_installed("openssl"):
        return (
            "[!] OpenSSL is not installed.\n"
            "    Install it with: sudo apt install openssl"
        )

    # Ensure we have a port
    if ":" not in target:
        target = f"{target}:443"

    safe_target = shlex.quote(target)

    # Run openssl s_client
    formatter.print_info(f"Checking TLS certificate for {target}...")

    stdout, stderr, _ = ToolRunner.run_shell(
        f"echo | openssl s_client -connect {safe_target} -servername {safe_target.split(':')[0]} 2>&1",
        timeout=30,
    )

    output = stdout if stdout.strip() else ""
    if stderr and not stdout:
        output = stderr

    if not output.strip():
        return (
            "[!] No TLS certificate data obtained.\n"
            "    Check that the target is reachable on port 443."
        )

    # Send to AI for analysis
    return analyze(output, system_prompt)
