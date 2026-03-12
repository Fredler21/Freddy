"""WHOIS lookup command — queries domain WHOIS information."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import install_hint
from modules.tool_runner import ToolRunner


def run_whois(domain: str, system_prompt: str) -> AnalysisResult:
    """
    Query WHOIS information for a domain.
    
    Args:
        domain: Domain to query
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of WHOIS information
    """
    if not ToolRunner.is_installed("whois"):
        return AnalysisResult(
            report=f"[!] Whois is not installed. {install_hint('whois')}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    formatter = OutputFormatter()

    formatter.print_info(f"Querying WHOIS for {domain}...")

    stdout, stderr, returncode = ToolRunner.run(ToolRunner.build_command("whois", domain), timeout=60)

    output = stdout if stdout.strip() else ""
    if not output.strip() and stderr:
        output = stderr

    if not output.strip():
        return AnalysisResult(
            report="[!] No WHOIS data obtained. Check that the domain is valid and the whois server is accessible.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=output,
        system_prompt=system_prompt,
        command_name="whois",
        target=domain,
        task_instruction="Analyze this WHOIS information from a defensive perspective, focusing on exposure, ownership context, and operational risk clues.",
    )
