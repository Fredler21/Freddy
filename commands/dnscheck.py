"""DNS check command — analyzes DNS records and resolution."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import install_hint
from modules.tool_runner import ToolRunner


def run_dnscheck(domain: str, system_prompt: str) -> AnalysisResult:
    """
    Check DNS records and resolution.
    
    Args:
        domain: Domain to check
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of DNS configuration
    """
    formatter = OutputFormatter()
    dns_data = []

    # 1. dig
    if ToolRunner.is_installed("dig"):
        formatter.print_info("Running dig...")
        stdout, _, _ = ToolRunner.run(ToolRunner.build_command("dig", domain), timeout=30)
        if stdout.strip():
            dns_data.append("=== DIG OUTPUT ===\n" + stdout)

    # 2. nslookup  
    if ToolRunner.is_installed("nslookup"):
        formatter.print_info("Running nslookup...")
        stdout, _, _ = ToolRunner.run(ToolRunner.build_command("nslookup", domain), timeout=30)
        if stdout.strip():
            dns_data.append("=== NSLOOKUP OUTPUT ===\n" + stdout)

    # 3. host
    if ToolRunner.is_installed("host"):
        formatter.print_info("Running host...")
        stdout, _, _ = ToolRunner.run(ToolRunner.build_command("host", domain), timeout=30)
        if stdout.strip():
            dns_data.append("=== HOST OUTPUT ===\n" + stdout)

    combined_output = "\n".join(dns_data)

    if not combined_output.strip():
        return AnalysisResult(
            report=(
                "[!] DNS check produced no usable output. "
                f"Tool hints: {install_hint('dig')} {install_hint('host')} Native 'nslookup' may still be available on Windows."
            ),
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=combined_output,
        system_prompt=system_prompt,
        command_name="dnscheck",
        target=domain,
        task_instruction="Analyze these DNS results for misconfiguration, exposure, and infrastructure hardening guidance.",
    )
