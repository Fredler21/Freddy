"""Web check command — analyzes web server security."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import install_hint
from modules.tool_runner import ToolRunner


def run_webcheck(target: str, system_prompt: str) -> AnalysisResult:
    """
    Run web security checks on a target using available tools.
    
    Args:
        target: Target URL or domain
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of web server security
    """
    formatter = OutputFormatter()
    web_data = []

    # 1. whatweb
    if ToolRunner.is_installed("whatweb"):
        formatter.print_info("Running whatweb...")
        stdout, stderr, _ = ToolRunner.run(ToolRunner.build_command("whatweb", target), timeout=60)
        if stdout.strip():
            web_data.append("=== WHATWEB OUTPUT ===\n" + stdout)
    else:
        formatter.print_warning("whatweb not installed")

    # 2. nikto
    if ToolRunner.is_installed("nikto"):
        formatter.print_info("Running nikto (this may take a while)...")
        stdout, stderr, _ = ToolRunner.run(
            ToolRunner.build_command("nikto", "-h", target), timeout=120
        )
        if stdout.strip():
            web_data.append("=== NIKTO OUTPUT ===\n" + stdout)
    else:
        formatter.print_warning("nikto not installed")

    # 3. curl for headers
    if ToolRunner.is_installed("curl"):
        formatter.print_info("Checking HTTP headers...")
        stdout, stderr, _ = ToolRunner.run(
            ToolRunner.build_command("curl", "-I", "-s", target),
            timeout=30,
        )
        if stdout.strip():
            web_data.append("=== HTTP HEADERS ===\n" + stdout)

    combined_output = "\n".join(web_data)

    if not combined_output.strip():
        return AnalysisResult(
            report=(
                "[!] Web check produced no usable output. "
                f"Tool hints: {install_hint('whatweb')} {install_hint('nikto')} {install_hint('curl')}"
            ),
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=combined_output,
        system_prompt=system_prompt,
        command_name="webcheck",
        target=target,
        task_instruction="Analyze this web security evidence with emphasis on exposed admin paths, HTTP hardening gaps, and web attack surface reduction.",
    )
