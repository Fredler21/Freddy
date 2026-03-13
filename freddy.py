#!/usr/bin/env python3
"""Freddy CLI entrypoint."""

from __future__ import annotations

import re

import typer
from rich.console import Console

from ai_engine import load_system_prompt
from commands.analyze import run_file_analysis
from commands.audit import run_audit
from commands.dnscheck import run_dnscheck
from commands.host_audit import run_host_audit
from commands.investigate import run_investigate
from commands.logs import run_logs
from commands.ports import run_ports
from commands.recon import run_recon
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
MIN_KNOWLEDGE_SCORE = 0.12
_STARTUP_SHOWN = False


def _confirm_action(prompt_text: str, assume_yes: bool = False) -> bool:
    """Ask the user to confirm a command action unless bypassed."""
    if assume_yes:
        return True
    return typer.confirm(prompt_text, default=True)


def _prepare_model_prompt(action_label: str) -> str | None:
    """Return system prompt for model-backed commands or show guided API setup help."""
    if not get_config().get("api_key_set", False):
        formatter.print_error(
            f"{action_label} requires AI analysis, but ANTHROPIC_API_KEY is not set."
        )
        formatter.print_section(
            "Enable AI Analysis",
            "Set your API key in the current shell:\n"
            "export ANTHROPIC_API_KEY='your_key_here'\n\n"
            "Or place it in a local .env file:\n"
            "ANTHROPIC_API_KEY=your_key_here",
            style="yellow",
        )
        formatter.print_section(
            "Use Freddy Right Now (No API Key)",
            "- python3 freddy.py knowledge-search \"ssh hardening\"\n"
            "- python3 freddy.py learn\n"
            "- python3 freddy.py history\n"
            "- python3 freddy.py memory-stats\n"
            "- python3 freddy.py walkthrough",
            style="cyan",
        )
        return None

    validate_config()
    return load_system_prompt()


def _maybe_print_startup_banner(no_banner: bool, banner_style: str = "auto") -> None:
    """Render startup banner once per process unless disabled."""
    global _STARTUP_SHOWN
    if no_banner or _STARTUP_SHOWN:
        return
    formatter.print_startup_screen(version="2.0.0", banner_style=banner_style)
    _STARTUP_SHOWN = True


def _run_welcome_flow(no_banner: bool, banner_style: str = "auto") -> None:
    """Show introduction and ask what the user wants to start."""
    _maybe_print_startup_banner(no_banner, banner_style=banner_style)

    formatter.print_section(
        "Welcome",
        "Freddy is your AI cybersecurity terminal copilot.\n"
        "I can guide you step-by-step, run checks safely, and explain results in plain language.",
        style="cyan",
    )

    formatter.print_section(
        "What Freddy Can Do",
        "- Guided workflows: walkthrough + safety confirmations before execution\n"
        "- Network and recon: scan, recon, ports, webcheck, tlscheck, dnscheck, whois\n"
        "- Host assessment: audit and host-audit for local security posture\n"
        "- Artifact analysis: analyze, logs, investigate for files and tool outputs\n"
        "- Knowledge system: learn indexing + knowledge-search from local docs\n"
        "- Operational memory: history and memory-stats for recurring issues\n"
        "- Premium terminal UX: adaptive banner, startup intro, and quick-start menu",
        style="blue",
    )

    console.print("[bold]Which one do you want to start today?[/bold]")
    console.print("1) Guided walkthrough (recommended)")
    console.print("2) Quick network scan")
    console.print("3) Full recon")
    console.print("4) Ask a knowledge question")
    console.print("5) Local security audit")
    console.print("0) Exit")

    choice = typer.prompt("Enter choice", default="1").strip()

    if choice == "0":
        formatter.print_info("No problem. Run 'python3 freddy.py' anytime to start again.")
        return
    if choice == "1":
        walkthrough()
        return
    if choice == "2":
        target = typer.prompt("Target host/IP/subnet (example: 192.168.1.0/24)").strip()
        scan(target, yes=True)
        return
    if choice == "3":
        target = typer.prompt("Recon target host/IP/domain").strip()
        recon(target, yes=True)
        return
    if choice == "4":
        query = typer.prompt("Enter your cybersecurity question").strip()
        knowledge_search(query, yes=True)
        return
    if choice == "5":
        audit(yes=True)
        return

    formatter.print_warning("Invalid choice. Run 'python3 freddy.py' and choose 0-5.")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", help="Disable Freddy startup banner"),
    banner_style: str = typer.Option(
        "auto",
        "--banner-style",
        help="Banner style: auto, max, or compact",
    ),
) -> None:
    """Global Freddy options applied before command execution."""
    if ctx.resilient_parsing:
        return
    if ctx.invoked_subcommand:
        _maybe_print_startup_banner(no_banner, banner_style=banner_style)
        return
    _run_welcome_flow(no_banner, banner_style=banner_style)


def _clean_knowledge_line(line: str) -> str:
    """Normalize a retrieved line into clean answer text."""
    cleaned = line.strip()
    if not cleaned:
        return ""
    if cleaned.startswith("#"):
        return ""
    cleaned = re.sub(r"^[-*•]+\s*", "", cleaned)
    cleaned = re.sub(r"^\d+[.)]\s*", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _is_ssh_question(query: str) -> bool:
    q = query.lower()
    return "ssh" in q or "sshd" in q


def _build_local_knowledge_answer(query: str, matches: list) -> str:
    """Build a direct local answer from top retrieved knowledge chunks.

    This avoids external API usage and keeps responses grounded in indexed docs.
    """
    top = matches[:5]
    snippets: list[str] = []
    sources: list[str] = []
    seen: set[str] = set()

    for match in top:
        sources.append(match.source)
        for line in match.document.splitlines():
            cleaned = _clean_knowledge_line(line)
            if not cleaned or len(cleaned) < 5:
                continue
            key = cleaned.casefold()
            if key in seen:
                continue
            seen.add(key)
            snippets.append(cleaned)
            if len(snippets) >= 16:
                break
        if len(snippets) >= 16:
            break

    if not snippets:
        return (
            f"I found knowledge sources relevant to '{query}', but could not extract enough "
            "clear text to synthesize an answer. Try a more specific question."
        )

    unique_sources = ", ".join(dict.fromkeys(sources))

    # Premium local answer format for SSH-related questions.
    if _is_ssh_question(query):
        key_actions = []
        for line in snippets:
            lower = line.lower()
            if any(
                token in lower
                for token in (
                    "permitrootlogin",
                    "passwordauthentication",
                    "pubkeyauthentication",
                    "maxauthtries",
                    "allowusers",
                    "allowgroups",
                    "logingracetime",
                    "fail2ban",
                    "firewall",
                    "management network",
                )
            ):
                key_actions.append(line)
            if len(key_actions) >= 6:
                break
        if not key_actions:
            key_actions = snippets[:6]

        action_block = "\n".join(f"- {item}" for item in key_actions)
        command_block = (
            "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak\n"
            "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
            "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
            "sudo sed -i 's/^#\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config\n"
            "sudo grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' | sudo tee -a /etc/ssh/sshd_config\n"
            "sudo grep -q '^LoginGraceTime' /etc/ssh/sshd_config || echo 'LoginGraceTime 30' | sudo tee -a /etc/ssh/sshd_config\n"
            "sudo systemctl restart ssh || sudo systemctl restart sshd\n"
            "sudo ufw allow from <ADMIN_IP> to any port 22 proto tcp\n"
            "sudo ufw deny 22/tcp\n"
            "sudo systemctl enable --now fail2ban"
        )
        verify_block = (
            "sudo sshd -t\n"
            "ss -tulpn | grep ':22'\n"
            "sudo grep -E 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|LoginGraceTime' /etc/ssh/sshd_config\n"
            "sudo fail2ban-client status\n"
            "sudo ufw status verbose"
        )
        return (
            f"Direct answer for '{query}':\n\n"
            "Priority SSH hardening actions:\n"
            f"{action_block}\n\n"
            "Recommended Ubuntu command sequence:\n"
            f"{command_block}\n\n"
            "Verification commands:\n"
            f"{verify_block}\n\n"
            f"Knowledge used: {unique_sources}"
        )

    # Generic premium local answer format for all other questions.
    key_points = snippets[:8]
    key_block = "\n".join(f"- {item}" for item in key_points)
    return (
        f"Direct answer for '{query}':\n\n"
        "Best evidence-backed points from Freddy's local knowledge:\n"
        f"{key_block}\n\n"
        f"Knowledge used: {unique_sources}"
    )


def print_result(result: AnalysisResult) -> None:
    """Render an analysis result with Freddy formatting."""
    formatter.print_analysis(
        result.report,
        knowledge_applied=result.knowledge_used,
        rule_finding_count=len(result.rule_findings),
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host or IP address"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Scan a target with Nmap and analyze open ports and services."""
    if not _confirm_action(f"Do you want me to scan this target: {target}?", assume_yes=yes):
        formatter.print_warning("Scan canceled by user.")
        return
    prompt = _prepare_model_prompt("Scan")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Scanning {target} with Nmap...[/bold cyan]\n")
    print_result(run_scan(target, prompt))


@app.command()
def ports(
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """List and analyze open ports on the local system."""
    if not _confirm_action("Do you want me to analyze open ports on this machine?", assume_yes=yes):
        formatter.print_warning("Ports analysis canceled by user.")
        return
    prompt = _prepare_model_prompt("Ports analysis")
    if not prompt:
        return
    console.print("\n[bold cyan]Analyzing local open ports...[/bold cyan]\n")
    print_result(run_ports(prompt))


@app.command()
def analyze(
    file: str = typer.Argument(..., help="Path to the file to analyze"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Analyze any file such as logs, Nmap output, or tool results."""
    if not _confirm_action(f"Do you want me to analyze this file: {file}?", assume_yes=yes):
        formatter.print_warning("File analysis canceled by user.")
        return
    prompt = _prepare_model_prompt("File analysis")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Analyzing {file}...[/bold cyan]\n")
    print_result(run_file_analysis(file, prompt))


@app.command()
def audit(
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Run a combined local system security audit."""
    if not _confirm_action("Do you want me to run a local security audit on this machine?", assume_yes=yes):
        formatter.print_warning("Audit canceled by user.")
        return
    prompt = _prepare_model_prompt("Local security audit")
    if not prompt:
        return
    console.print("\n[bold cyan]Running local security audit...[/bold cyan]\n")
    print_result(run_audit(prompt))


@app.command()
def webcheck(
    target: str = typer.Argument(..., help="Target URL or domain"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Run web security checks and analyze the results."""
    if not _confirm_action(f"Do you want me to run web security checks for: {target}?", assume_yes=yes):
        formatter.print_warning("Web check canceled by user.")
        return
    prompt = _prepare_model_prompt("Web security check")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Checking web security for {target}...[/bold cyan]\n")
    print_result(run_webcheck(target, prompt))


@app.command()
def tlscheck(
    target: str = typer.Argument(..., help="Target host:port or domain"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Check TLS and certificate security."""
    if not _confirm_action(f"Do you want me to check TLS security for: {target}?", assume_yes=yes):
        formatter.print_warning("TLS check canceled by user.")
        return
    prompt = _prepare_model_prompt("TLS check")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Checking TLS for {target}...[/bold cyan]\n")
    print_result(run_tlscheck(target, prompt))


@app.command()
def dnscheck(
    domain: str = typer.Argument(..., help="Domain to check"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Check DNS records and defensive posture."""
    if not _confirm_action(f"Do you want me to check DNS records for: {domain}?", assume_yes=yes):
        formatter.print_warning("DNS check canceled by user.")
        return
    prompt = _prepare_model_prompt("DNS check")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Checking DNS for {domain}...[/bold cyan]\n")
    print_result(run_dnscheck(domain, prompt))


@app.command()
def whois(
    domain: str = typer.Argument(..., help="Domain to look up"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Look up WHOIS information and analyze it."""
    if not _confirm_action(f"Do you want me to run WHOIS lookup for: {domain}?", assume_yes=yes):
        formatter.print_warning("WHOIS lookup canceled by user.")
        return
    prompt = _prepare_model_prompt("WHOIS lookup")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Looking up WHOIS for {domain}...[/bold cyan]\n")
    print_result(run_whois(domain, prompt))


@app.command()
def logs(
    file: str = typer.Argument(..., help="Path to the log file to analyze"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Analyze a log file for security issues."""
    if not _confirm_action(f"Do you want me to analyze this log file: {file}?", assume_yes=yes):
        formatter.print_warning("Log analysis canceled by user.")
        return
    prompt = _prepare_model_prompt("Log analysis")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Analyzing logs from {file}...[/bold cyan]\n")
    print_result(run_logs(file, prompt))


@app.command("learn")
def learn(
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Index Freddy knowledge and vulnerability markdown into the local vector store."""
    if not _confirm_action("Do you want me to build/rebuild the local knowledge index now?", assume_yes=yes):
        formatter.print_warning("Learn/indexing canceled by user.")
        return
    validate_paths()
    console.print("\n[bold cyan]Building Freddy knowledge index...[/bold cyan]\n")
    engine = KnowledgeEngine()
    stats = engine.index_all()
    skipped = stats.get("skipped", 0)
    skip_note = f" ({skipped} skipped)" if skipped else ""
    formatter.print_success(
        f"Indexed {stats['files']} files into {stats['chunks']} chunks in the local vector store{skip_note}."
    )


@app.command("knowledge-search")
def knowledge_search(
    query: str = typer.Argument(..., help="Cybersecurity question or topic"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Ask Freddy a direct question using only local indexed knowledge (no API call)."""
    if not _confirm_action(f"Do you want me to search local knowledge for: {query}?", assume_yes=yes):
        formatter.print_warning("Knowledge search canceled by user.")
        return
    validate_paths()
    engine = KnowledgeEngine()
    matches = engine.query(query)
    if not matches or matches[0].score < MIN_KNOWLEDGE_SCORE:
        formatter.print_warning(
            "Freddy could not find enough relevant local knowledge to answer this question. "
            "Try rewording your question or add/index more knowledge files with 'learn'."
        )
        return

    answer = _build_local_knowledge_answer(query, matches)
    formatter.print_section("Freddy Answer", answer, style="green")

    # Always show source transparency so users can inspect provenance.
    rows = [(match.category, match.source, f"{match.score:.2f}") for match in matches]
    formatter.print_table(rows, ["Category", "Source", "Score"], title="Answer Sources")


@app.command()
def history(
    target: str | None = typer.Option(None, "--target", help="Filter stored history by target"),
    limit: int = typer.Option(20, "--limit", min=1, max=100, help="Maximum records to show"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Show Freddy's stored scan and analysis history."""
    scope = f" for target {target}" if target else ""
    if not _confirm_action(f"Do you want me to show Freddy history{scope}?", assume_yes=yes):
        formatter.print_warning("History view canceled by user.")
        return
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


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target host, IP, or URL to recon"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Full external reconnaissance: nmap, whatweb, nikto, TLS, DNS, and WHOIS correlated."""
    if not _confirm_action(f"Do you want me to run full reconnaissance against: {target}?", assume_yes=yes):
        formatter.print_warning("Recon canceled by user.")
        return
    prompt = _prepare_model_prompt("Recon")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Running full recon against {target}...[/bold cyan]\n")
    print_result(run_recon(target, prompt))


@app.command("host-audit")
def host_audit(
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Comprehensive local host security audit: firewall, services, SSH, containers, and more."""
    if not _confirm_action("Do you want me to run a comprehensive host audit on this machine?", assume_yes=yes):
        formatter.print_warning("Host audit canceled by user.")
        return
    prompt = _prepare_model_prompt("Host audit")
    if not prompt:
        return
    console.print("\n[bold cyan]Running comprehensive host audit...[/bold cyan]\n")
    print_result(run_host_audit(prompt))


@app.command()
def investigate(
    file: str = typer.Argument(..., help="Path to artifact file (log, config, or tool output)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Deep security investigation of a single artifact file with indicator extraction."""
    if not _confirm_action(f"Do you want me to investigate this artifact: {file}?", assume_yes=yes):
        formatter.print_warning("Investigation canceled by user.")
        return
    prompt = _prepare_model_prompt("Investigation")
    if not prompt:
        return
    console.print(f"\n[bold cyan]Investigating {file}...[/bold cyan]\n")
    print_result(run_investigate(file, prompt))


@app.command("memory-stats")
def memory_stats(
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts"),
) -> None:
    """Show Freddy memory statistics: total scans, unique targets, and top findings."""
    if not _confirm_action("Do you want me to show Freddy memory statistics?", assume_yes=yes):
        formatter.print_warning("Memory stats canceled by user.")
        return
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


@app.command("walkthrough")
def walkthrough() -> None:
    """Interactive guided mode to run Freddy actions step-by-step."""
    console.print("\n[bold cyan]Freddy Guided Walkthrough[/bold cyan]")
    console.print("I will guide you step-by-step and run commands for you.\n")

    while True:
        console.print("[bold]Choose an action:[/bold]")
        console.print("1) Scan target (nmap + analysis)")
        console.print("2) Full recon target")
        console.print("3) Check local open ports")
        console.print("4) Run local audit")
        console.print("5) Web security check")
        console.print("6) TLS check")
        console.print("7) DNS check")
        console.print("8) WHOIS lookup")
        console.print("9) Analyze file/log")
        console.print("10) Build/rebuild knowledge index")
        console.print("11) Ask local knowledge question")
        console.print("12) Show history")
        console.print("13) Show memory stats")
        console.print("0) Exit walkthrough")

        choice = typer.prompt("Enter choice", default="1").strip()

        if choice == "0":
            formatter.print_success("Walkthrough finished.")
            return

        if choice == "1":
            target = typer.prompt("Target host/IP/subnet (example: 192.168.1.0/24)").strip()
            if typer.confirm(f"Run scan on {target}?", default=True):
                scan(target, yes=True)
        elif choice == "2":
            target = typer.prompt("Recon target host/IP/domain").strip()
            if typer.confirm(f"Run full recon against {target}?", default=True):
                recon(target, yes=True)
        elif choice == "3":
            if typer.confirm("Analyze local open ports now?", default=True):
                ports(yes=True)
        elif choice == "4":
            if typer.confirm("Run local system audit now?", default=True):
                audit(yes=True)
        elif choice == "5":
            target = typer.prompt("Web target URL/domain (example: https://example.com)").strip()
            if typer.confirm(f"Run web security check for {target}?", default=True):
                webcheck(target, yes=True)
        elif choice == "6":
            target = typer.prompt("TLS target host:port or domain").strip()
            if typer.confirm(f"Run TLS check for {target}?", default=True):
                tlscheck(target, yes=True)
        elif choice == "7":
            domain = typer.prompt("Domain for DNS check").strip()
            if typer.confirm(f"Run DNS check for {domain}?", default=True):
                dnscheck(domain, yes=True)
        elif choice == "8":
            domain = typer.prompt("Domain for WHOIS lookup").strip()
            if typer.confirm(f"Run WHOIS lookup for {domain}?", default=True):
                whois(domain, yes=True)
        elif choice == "9":
            file = typer.prompt("Path to file/log/tool output").strip()
            if typer.confirm(f"Analyze file {file}?", default=True):
                analyze(file, yes=True)
        elif choice == "10":
            if typer.confirm("Build/rebuild local knowledge index now?", default=True):
                learn(yes=True)
        elif choice == "11":
            query = typer.prompt("Enter your cybersecurity question").strip()
            if typer.confirm(f"Search local knowledge for: {query}?", default=True):
                knowledge_search(query, yes=True)
        elif choice == "12":
            target = typer.prompt("Optional target filter (leave empty for all)", default="").strip()
            if typer.confirm("Show history now?", default=True):
                history(target=target or None, yes=True)
        elif choice == "13":
            if typer.confirm("Show memory stats now?", default=True):
                memory_stats(yes=True)
        else:
            formatter.print_warning("Invalid choice. Please enter a number from 0 to 13.")
            continue

        if not typer.confirm("Do you want to run another guided action?", default=True):
            formatter.print_success("Walkthrough finished.")
            return
        console.print()


if __name__ == "__main__":
    app()
