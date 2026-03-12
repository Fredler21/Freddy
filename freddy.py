#!/usr/bin/env python3
"""
Freddy — AI Cybersecurity Terminal Copilot for Linux.

A powerful terminal assistant for security professionals that analyzes
security tool outputs, logs, and system configurations to detect vulnerabilities,
misconfigurations, and attack indicators.

Usage:
    python3 freddy.py scan <target>
    python3 freddy.py ports
    python3 freddy.py analyze <file>
    python3 freddy.py audit
    python3 freddy.py webcheck <target>
    python3 freddy.py tlscheck <target>
    python3 freddy.py dnscheck <domain>
    python3 freddy.py whois <domain>
    python3 freddy.py logs <file>
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config import validate_config, get_config
from ai_engine import load_system_prompt
from modules.output_formatter import OutputFormatter
from commands.scan import run_scan
from commands.ports import run_ports
from commands.analyze import run_file_analysis
from commands.audit import run_audit
from commands.webcheck import run_webcheck
from commands.tlscheck import run_tlscheck
from commands.dnscheck import run_dnscheck
from commands.whois_lookup import run_whois
from commands.logs import run_logs

# --- Setup ---
app = typer.Typer(
    name="freddy",
    help="Freddy — AI Cybersecurity Terminal Copilot",
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console()
formatter = OutputFormatter()


def print_result(analysis: str):
    """Print the AI analysis with rich formatting."""
    formatter.print_analysis(analysis)


# --- CLI Commands ---


@app.command()
def scan(target: str = typer.Argument(..., help="Target host or IP address")):
    """Scan a target with Nmap and analyze open ports/services."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]🔍 Scanning {target} with Nmap...[/bold cyan]\n")
    analysis = run_scan(target, prompt)
    print_result(analysis)


@app.command()
def ports():
    """List and analyze open ports on the local system."""
    validate_config()
    prompt = load_system_prompt()

    console.print("\n[bold cyan]📍 Analyzing open ports...[/bold cyan]\n")
    analysis = run_ports(prompt)
    print_result(analysis)


@app.command()
def analyze(
    file: str = typer.Argument(..., help="Path to the file to analyze")
):
    """Analyze any file (logs, nmap output, etc.)."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]📋 Analyzing {file}...[/bold cyan]\n")
    analysis = run_file_analysis(file, prompt)
    print_result(analysis)


@app.command()
def audit():
    """Run a comprehensive local system security audit."""
    validate_config()
    prompt = load_system_prompt()

    console.print(
        "\n[bold cyan]🔐 Running system security audit...[/bold cyan]\n"
    )
    analysis = run_audit(prompt)
    print_result(analysis)


@app.command()
def webcheck(target: str = typer.Argument(..., help="Target URL or domain")):
    """Run web security checks (whatweb, nikto, etc.)."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]🌐 Checking web security for {target}...[/bold cyan]\n")
    analysis = run_webcheck(target, prompt)
    print_result(analysis)


@app.command()
def tlscheck(target: str = typer.Argument(..., help="Target host:port or domain")):
    """Check TLS/SSL certificate and configuration."""
    validate_config()
    prompt = load_system_prompt()

    console.print(
        f"\n[bold cyan]🔒 Checking TLS/SSL for {target}...[/bold cyan]\n"
    )
    analysis = run_tlscheck(target, prompt)
    print_result(analysis)


@app.command()
def dnscheck(domain: str = typer.Argument(..., help="Domain to check")):
    """Check DNS records and configuration."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]📡 Checking DNS for {domain}...[/bold cyan]\n")
    analysis = run_dnscheck(domain, prompt)
    print_result(analysis)


@app.command()
def whois(domain: str = typer.Argument(..., help="Domain to look up")):
    """Look up WHOIS information for a domain."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]🔎 Looking up WHOIS for {domain}...[/bold cyan]\n")
    analysis = run_whois(domain, prompt)
    print_result(analysis)


@app.command()
def logs(
    file: str = typer.Argument(..., help="Path to the log file to analyze")
):
    """Analyze a log file for security issues."""
    validate_config()
    prompt = load_system_prompt()

    console.print(f"\n[bold cyan]📜 Analyzing logs from {file}...[/bold cyan]\n")
    analysis = run_logs(file, prompt)
    print_result(analysis)


@app.command()
def version():
    """Show version information."""
    console.print("\n[bold cyan]Freddy[/bold cyan] v1.0.0")
    console.print("AI Cybersecurity Terminal Copilot")
    console.print("https://github.com/yourname/Freddy\n")


@app.command()
def info():
    """Show configuration information."""
    console.print("\n[bold cyan]Freddy Configuration[/bold cyan]\n")
    try:
        config = get_config()
        console.print(f"API Key Set: {'✓' if config['api_key_set'] else '✗'}")
        console.print(f"Model: {config['model']}")
        console.print(f"Max Tokens: {config['max_tokens']}")
        console.print(f"System Prompt: {config['system_prompt_path']}")
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
    console.print()


if __name__ == "__main__":
    app()



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
