import subprocess
from ai_engine import analyze


def run_audit(prompt: str) -> str:
    """Run a basic system security audit and analyze results."""
    checks = []

    # Open ports
    ports = subprocess.run(
        ["ss", "-tulpn"], capture_output=True, text=True, timeout=30
    )
    checks.append("=== Open Ports ===\n" + ports.stdout)

    # Firewall status
    ufw = subprocess.run(
        ["ufw", "status"], capture_output=True, text=True, timeout=15
    )
    checks.append("=== Firewall (UFW) ===\n" + ufw.stdout)

    # Running services
    services = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    checks.append("=== Running Services ===\n" + services.stdout)

    # Users with login shells
    try:
        with open("/etc/passwd", "r") as f:
            users = [
                line for line in f
                if line.strip().endswith(("/bin/bash", "/bin/sh", "/bin/zsh"))
            ]
        checks.append("=== Users With Login Shells ===\n" + "".join(users))
    except FileNotFoundError:
        checks.append("=== Users With Login Shells ===\n/etc/passwd not found")

    combined = "\n\n".join(checks)
    return analyze(combined, prompt)
