#!/usr/bin/env python3
"""Freddy — AI Cybersecurity Terminal Copilot."""

import os
import typer
from rich import print as rprint
from commands.scan import run_scan
from commands.ports import run_ports
from commands.logs import run_log_analysis
from commands.audit import run_audit

app = typer.Typer(help="Freddy — AI Cybersecurity Terminal Copilot")

PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "system_prompt.txt")

with open(PROMPT_PATH) as f:
    SYSTEM_PROMPT = f.read()


@app.command()
def scan(target: str = typer.Argument(..., help="Target host or IP to scan")):
    """Run an Nmap scan on a target and analyze results."""
    rprint(f"[cyan]🔍 Scanning {target}...[/cyan]")
    analysis = run_scan(target, SYSTEM_PROMPT)
    rprint("[green]━━━ Freddy Analysis ━━━[/green]")
    rprint(analysis)


@app.command()
def ports():
    """List open ports and services, then analyze them."""
    rprint("[cyan]🔍 Checking open ports...[/cyan]")
    analysis = run_ports(SYSTEM_PROMPT)
    rprint("[green]━━━ Freddy Analysis ━━━[/green]")
    rprint(analysis)


@app.command()
def analyze(log_path: str = typer.Argument(..., help="Path to log file (e.g. /var/log/auth.log)")):
    """Analyze a log file for security issues."""
    rprint(f"[cyan]🔍 Analyzing {log_path}...[/cyan]")
    analysis = run_log_analysis(log_path, SYSTEM_PROMPT)
    rprint("[green]━━━ Freddy Analysis ━━━[/green]")
    rprint(analysis)


@app.command()
def audit():
    """Run a system security audit (ports, firewall, services, users)."""
    rprint("[cyan]🔍 Running system audit...[/cyan]")
    analysis = run_audit(SYSTEM_PROMPT)
    rprint("[green]━━━ Freddy Analysis ━━━[/green]")
    rprint(analysis)


if __name__ == "__main__":
    app()
