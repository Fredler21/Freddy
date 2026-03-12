#!/usr/bin/env python3
"""Freddy — AI Cybersecurity Terminal Copilot."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config import validate_config
from ai_engine import load_system_prompt
from commands.scan import run_scan
from commands.ports import run_ports
from commands.analyze import run_file_analysis
from commands.audit import run_audit

# --- Setup ---
app = typer.Typer(
    name="freddy",
    help="Freddy — AI Cybersecurity Terminal Copilot",
    add_completion=False,
)
console = Console()


def _print_banner():
    """Display the Freddy banner."""
    banner = Text("FREDDY — Cyber Intelligence Report", style="bold cyan")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


def _print_result(analysis: str):
    """Print the AI analysis with rich formatting."""
    console.print()
    _print_banner()
    console.print()
    console.print(Panel(analysis, title="[bold green]Analysis[/bold green]", border_style="green", padding=(1, 2)))
    console.print()


# --- CLI Commands ---

@app.command()
def scan(target: str = typer.Argument(..., help="Target host or IP to scan")):
    """Run an Nmap service scan on a target and analyze the results."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]🔍 Scanning {target} with Nmap...[/bold cyan]\n")
    analysis = run_scan(target, prompt)
    _print_result(analysis)


@app.command()
def ports():
    """List open ports and services, then analyze them."""
    validate_config()
    prompt = load_system_prompt()

    console.print("\n[bold cyan]🔍 Listing open ports...[/bold cyan]\n")
    analysis = run_ports(prompt)
    _print_result(analysis)


@app.command()
def analyze(file_path: str = typer.Argument(..., help="Path to file (log, scan output, etc.)")):
    """Analyze a file (logs, scan output) for security issues."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]🔍 Analyzing {file_path}...[/bold cyan]\n")
    analysis = run_file_analysis(file_path, prompt)
    _print_result(analysis)


@app.command()
def audit():
    """Run a full system security audit (ports, firewall, services, users)."""
    validate_config()
    prompt = load_system_prompt()

    console.print("\n[bold cyan]🔍 Running system security audit...[/bold cyan]\n")
    analysis = run_audit(prompt)
    _print_result(analysis)


if __name__ == "__main__":
    app()
