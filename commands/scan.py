"""Scan command — runs Nmap service detection against a target."""

import shlex
import shutil
import subprocess
from ai_engine import analyze


def run_scan(target: str, prompt: str) -> str:
    """Run an Nmap service version scan on the target and return AI analysis."""

    # Verify nmap is installed
    if not shutil.which("nmap"):
        return (
            "[!] Nmap is not installed.\n"
            "    Install it with:  sudo apt install nmap"
        )

    # Sanitize the target to prevent command injection
    safe_target = shlex.quote(target)

    try:
        scan = subprocess.run(
            ["nmap", "-sV", safe_target],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return "[!] Nmap scan timed out after 5 minutes."
    except OSError as e:
        return f"[!] Failed to run nmap: {e}"

    output = scan.stdout
    if scan.returncode != 0:
        output += f"\n[stderr]\n{scan.stderr}"

    if not output.strip():
        return "[!] Nmap produced no output. Check the target and try again."

    return analyze(output, prompt)
