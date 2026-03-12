#!/usr/bin/env python3
"""Freddy CLI entrypoint."""

from __future__ import annotations

import typer
from rich.console import Console

from ai_engine import load_system_prompt
from commands.analyze import run_file_analysis
from commands.audit import run_audit
from commands.dnscheck import run_dnscheck
from commands.logs import run_logs
from commands.ports import run_ports
from commands.scan import run_scan
from commands.tlscheck import run_tlscheck
from commands.webcheck import run_webcheck
from commands.whois_lookup import run_whois
from config import get_config, validate_config, validate_paths
from modules.intelligence_pipeline import AnalysisResult
from modules.knowledge_engine import KnowledgeEngine
from modules.memory_engine import MemoryEngine
from modules.output_formatter import OutputFormatter
from modules.platform_support import current_platform, is_linux_like
from modules.retrieval_formatter import format_history

app = typer.Typer(
    name="freddy",
    help="Freddy — AI Cybersecurity Terminal Copilot",
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console()
formatter = OutputFormatter()


def print_result(result: AnalysisResult) -> None:
    """Render an analysis result with Freddy formatting."""
    formatter.print_analysis(
        result.report,
        knowledge_applied=result.knowledge_used,
        rule_finding_count=len(result.rule_findings),
    )


@app.command()
def scan(target: str = typer.Argument(..., help="Target host or IP address")) -> None:
    """Scan a target with Nmap and analyze open ports and services."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Scanning {target} with Nmap...[/bold cyan]\n")
    print_result(run_scan(target, prompt))


@app.command()
def ports() -> None:
    """List and analyze open ports on the local system."""
    validate_config()
    prompt = load_system_prompt()
    console.print("\n[bold cyan]Analyzing local open ports...[/bold cyan]\n")
    print_result(run_ports(prompt))


@app.command()
def analyze(file: str = typer.Argument(..., help="Path to the file to analyze")) -> None:
    """Analyze any file such as logs, Nmap output, or tool results."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Analyzing {file}...[/bold cyan]\n")
    print_result(run_file_analysis(file, prompt))


@app.command()
def audit() -> None:
    """Run a combined local system security audit."""
    validate_config()
    prompt = load_system_prompt()
    console.print("\n[bold cyan]Running local security audit...[/bold cyan]\n")
    print_result(run_audit(prompt))


@app.command()
def webcheck(target: str = typer.Argument(..., help="Target URL or domain")) -> None:
    """Run web security checks and analyze the results."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Checking web security for {target}...[/bold cyan]\n")
    print_result(run_webcheck(target, prompt))


@app.command()
def tlscheck(target: str = typer.Argument(..., help="Target host:port or domain")) -> None:
    """Check TLS and certificate security."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Checking TLS for {target}...[/bold cyan]\n")
    print_result(run_tlscheck(target, prompt))


@app.command()
def dnscheck(domain: str = typer.Argument(..., help="Domain to check")) -> None:
    """Check DNS records and defensive posture."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Checking DNS for {domain}...[/bold cyan]\n")
    print_result(run_dnscheck(domain, prompt))


@app.command()
def whois(domain: str = typer.Argument(..., help="Domain to look up")) -> None:
    """Look up WHOIS information and analyze it."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Looking up WHOIS for {domain}...[/bold cyan]\n")
    print_result(run_whois(domain, prompt))


@app.command()
def logs(file: str = typer.Argument(..., help="Path to the log file to analyze")) -> None:
    """Analyze a log file for security issues."""
    validate_config()
    prompt = load_system_prompt()
    console.print(f"\n[bold cyan]Analyzing logs from {file}...[/bold cyan]\n")
    print_result(run_logs(file, prompt))


@app.command("learn")
def learn() -> None:
    """Index Freddy knowledge and vulnerability markdown into the local vector store."""
    validate_paths()
    console.print("\n[bold cyan]Building Freddy knowledge index...[/bold cyan]\n")
    engine = KnowledgeEngine()
    stats = engine.index_all()
    formatter.print_success(
        f"Indexed {stats['files']} files into {stats['chunks']} chunks in the local vector store."
    )


@app.command("knowledge-search")
def knowledge_search(query: str = typer.Argument(..., help="Cybersecurity question or topic")) -> None:
    """Search Freddy's local cybersecurity knowledge base."""
    validate_paths()
    engine = KnowledgeEngine()
    matches = engine.query(query)
    if not matches:
        formatter.print_warning(
            "No indexed knowledge found. Run Freddy's 'learn' command first or add relevant knowledge files."
        )
        return

    rows = [(match.category, match.source, f"{match.score:.2f}") for match in matches]
    formatter.print_table(rows, ["Category", "Source", "Score"], title="Knowledge Search Results")
    for match in matches:
        formatter.print_section(match.title, match.document, style="cyan")


@app.command()
def history(
    target: str | None = typer.Option(None, "--target", help="Filter stored history by target"),
    limit: int = typer.Option(20, "--limit", min=1, max=100, help="Maximum records to show"),
) -> None:
    """Show Freddy's stored scan and analysis history."""
    validate_paths()
    memory = MemoryEngine()
    records = memory.get_recent_scan_history(limit=limit, target=target)
    if not records:
        formatter.print_warning("No Freddy history records found yet.")
        return

    formatter.print_history_table(
        format_history(records),
        title="Freddy Scan History" if not target else f"Freddy Scan History: {target}",
    )
    for record in records[:5]:
        formatter.print_section(
            f"{record.command} -> {record.target}",
            f"Severity: {record.severity}\nSummary: {record.findings_summary}\nRemediation: {record.remediation_summary}",
            style="green",
        )


@app.command("memory-stats")
def memory_stats() -> None:
    """Show Freddy memory statistics: total scans, unique targets, and top findings."""
    validate_paths()
    memory = MemoryEngine()
    stats = memory.get_memory_stats()
    formatter.print_memory_stats(stats)


@app.command()
def version() -> None:
    """Show Freddy version information."""
    console.print("\n[bold cyan]Freddy[/bold cyan] v2.0.0")
    console.print("Knowledge-driven AI Cybersecurity Copilot\n")


@app.command()
def info() -> None:
    """Show Freddy configuration and runtime locations."""
    console.print("\n[bold cyan]Freddy Configuration[/bold cyan]\n")
    config = get_config()
    platform_name = current_platform()
    console.print(f"API Key Set: {'yes' if config['api_key_set'] else 'no'}")
    console.print(f"Current Platform: {platform_name}")
    console.print(f"Model: {config['model']}")
    console.print(f"Max Tokens: {config['max_tokens']}")
    console.print(f"Embedding Model: {config['embedding_model']}")
    console.print(f"System Prompt: {config['system_prompt_path']}")
    console.print(f"Knowledge Directory: {config['knowledge_dir']}")
    console.print(f"Vulnerability Directory: {config['vulnerability_dir']}")
    console.print(f"Vector Database: {config['vector_db_dir']}")
    console.print(f"Memory Database: {config['memory_db_path']}")
    if not is_linux_like():
        console.print(
            "Preferred Full-Feature Mode: use Linux or WSL for local host inspection commands such as ports and audit"
        )
    console.print()


if __name__ == "__main__":
    app()
