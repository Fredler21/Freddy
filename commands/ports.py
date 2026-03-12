"""Ports command — lists open ports/services and sends them for AI analysis."""

import shutil
import subprocess
from ai_engine import analyze


def run_ports(prompt: str) -> str:
    """List open ports/services with ss and return AI analysis."""

    # Verify ss is available
    if not shutil.which("ss"):
        return (
            "[!] 'ss' command not found.\n"
            "    Install it with:  sudo apt install iproute2"
        )

    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "[!] Port listing timed out."
    except OSError as e:
        return f"[!] Failed to run ss: {e}"

    output = result.stdout
    if result.returncode != 0:
        output += f"\n[stderr]\n{result.stderr}"

    if not output.strip():
        return "[!] No output from ss. You may need to run Freddy with sudo."

    return analyze(output, prompt)
