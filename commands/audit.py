"""Audit command — runs a system security audit and sends results for AI analysis."""

import subprocess
from ai_engine import analyze


def _run_cmd(cmd: list[str], label: str, timeout: int = 30) -> str:
    """Run a system command and return labelled output, handling errors gracefully."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip() if result.stdout else "(no output)"
        if result.returncode != 0 and result.stderr:
            output += f"\n[stderr] {result.stderr.strip()}"
        return f"=== {label} ===\n{output}"
    except FileNotFoundError:
        return f"=== {label} ===\n(command not found: {cmd[0]})"
    except subprocess.TimeoutExpired:
        return f"=== {label} ===\n(timed out)"


def run_audit(prompt: str) -> str:
    """Run a basic system security audit and return AI analysis."""
    checks = []

    # Open ports
    checks.append(_run_cmd(["ss", "-tulpn"], "Open Ports"))

    # Firewall status
    checks.append(_run_cmd(["ufw", "status"], "Firewall (UFW)"))

    # Running services
    checks.append(
        _run_cmd(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            "Running Services",
        )
    )

    # Users with login shells
    try:
        with open("/etc/passwd", "r") as f:
            users = [
                line for line in f
                if line.strip().endswith(("/bin/bash", "/bin/sh", "/bin/zsh"))
            ]
        checks.append("=== Users With Login Shells ===\n" + "".join(users))
    except FileNotFoundError:
        checks.append("=== Users With Login Shells ===\n(/etc/passwd not found)")
    except PermissionError:
        checks.append("=== Users With Login Shells ===\n(permission denied)")

    combined = "\n\n".join(checks)

    if not combined.strip():
        return "[!] Audit produced no output. Try running with sudo."

    return analyze(combined, prompt)
