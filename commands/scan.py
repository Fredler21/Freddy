import subprocess
import shlex
from ai_engine import analyze


def run_scan(target: str, prompt: str) -> str:
    """Run an Nmap service version scan on the target and analyze results."""
    safe_target = shlex.quote(target)
    scan = subprocess.run(
        ["nmap", "-sV", safe_target],
        capture_output=True,
        text=True,
        timeout=300,
    )

    output = scan.stdout
    if scan.returncode != 0:
        output += f"\n[stderr]\n{scan.stderr}"

    return analyze(output, prompt)
