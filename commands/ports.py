import subprocess
from ai_engine import analyze


def run_ports(prompt: str) -> str:
    """List open ports/services with ss and analyze them."""
    result = subprocess.run(
        ["ss", "-tulpn"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    output = result.stdout
    if result.returncode != 0:
        output += f"\n[stderr]\n{result.stderr}"

    return analyze(output, prompt)
