"""Automated Investigation Workflow — chains multiple security checks automatically."""

from __future__ import annotations

from dataclasses import dataclass, field

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.platform_support import install_hint, is_linux_like
from modules.tool_runner import ToolRunner


@dataclass(slots=True)
class WorkflowStep:
    name: str
    status: str  # pending, running, completed, skipped, failed
    output: str = ""
    error: str = ""


@dataclass(slots=True)
class InvestigationWorkflowResult:
    target: str
    steps: list[WorkflowStep] = field(default_factory=list)
    combined_evidence: str = ""
    analysis: AnalysisResult | None = None

    @property
    def completed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == "completed")

    @property
    def total_steps(self) -> int:
        return len(self.steps)


class AutoInvestigator:
    """Runs automated multi-tool investigation workflows."""

    def full_target_investigation(
        self,
        target: str,
        system_prompt: str,
        callback: object = None,
    ) -> InvestigationWorkflowResult:
        """Run a comprehensive automated investigation against a target.

        Workflow steps:
        1. Nmap port and service scan
        2. Web technology detection (whatweb)
        3. TLS/SSL inspection (openssl)
        4. DNS posture check (dig/nslookup)
        5. WHOIS lookup
        6. Vulnerability scan (nikto for web targets)
        """
        result = InvestigationWorkflowResult(target=target)
        evidence_parts: list[str] = []

        # Step 1: Nmap scan
        step = WorkflowStep(name="Nmap Port & Service Scan", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("nmap"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("nmap", "-sV", "-T4", target),
                timeout=300,
            )
            step.output = stdout
            if rc != 0 and stderr:
                step.output += f"\n[stderr] {stderr}"
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = f"nmap not installed. {install_hint('nmap')}"
        if step.output:
            evidence_parts.append(f"=== NMAP SCAN ===\n{step.output}")

        # Step 2: Web technology detection
        step = WorkflowStep(name="Web Technology Detection", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("whatweb"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("whatweb", "--color=never", target),
                timeout=60,
            )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        elif ToolRunner.is_installed("curl"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("curl", "-sI", "-L", "--max-time", "10", f"http://{target}"),
                timeout=15,
            )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = "No web detection tool available (whatweb or curl)"
        if step.output:
            evidence_parts.append(f"=== WEB DETECTION ===\n{step.output}")

        # Step 3: TLS/SSL inspection
        step = WorkflowStep(name="TLS/SSL Inspection", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("openssl"):
            # Check port 443 by default
            tls_target = f"{target}:443" if ":" not in target else target
            host_part = tls_target.split(":")[0]
            port_part = tls_target.split(":")[-1]
            stdout, stderr, rc = ToolRunner.run_shell(
                f"echo | openssl s_client -connect {host_part}:{port_part} -servername {host_part} 2>/dev/null | openssl x509 -noout -text 2>/dev/null",
                timeout=15,
            )
            step.output = stdout or stderr or ""
            step.status = "completed" if step.output.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = "openssl not installed"
        if step.output:
            evidence_parts.append(f"=== TLS INSPECTION ===\n{step.output}")

        # Step 4: DNS posture check
        step = WorkflowStep(name="DNS Posture Check", status="running")
        result.steps.append(step)
        dns_tool = None
        for tool in ("dig", "nslookup", "host"):
            if ToolRunner.is_installed(tool):
                dns_tool = tool
                break

        if dns_tool:
            if dns_tool == "dig":
                stdout, stderr, rc = ToolRunner.run(
                    ToolRunner.build_command("dig", target, "ANY", "+noall", "+answer"),
                    timeout=15,
                )
            elif dns_tool == "nslookup":
                stdout, stderr, rc = ToolRunner.run(
                    ToolRunner.build_command("nslookup", target),
                    timeout=15,
                )
            else:
                stdout, stderr, rc = ToolRunner.run(
                    ToolRunner.build_command("host", target),
                    timeout=15,
                )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = "No DNS tool available (dig, nslookup, or host)"
        if step.output:
            evidence_parts.append(f"=== DNS CHECK ===\n{step.output}")

        # Step 5: WHOIS lookup
        step = WorkflowStep(name="WHOIS Lookup", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("whois"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("whois", target),
                timeout=30,
            )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = f"whois not installed. {install_hint('whois')}"
        if step.output:
            evidence_parts.append(f"=== WHOIS ===\n{step.output}")

        # Step 6: Vulnerability scan (nikto for web targets)
        step = WorkflowStep(name="Web Vulnerability Scan (Nikto)", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("nikto"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("nikto", "-h", target, "-maxtime", "60s"),
                timeout=90,
            )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = f"nikto not installed. {install_hint('nikto')}"
        if step.output:
            evidence_parts.append(f"=== NIKTO SCAN ===\n{step.output}")

        # Combine all evidence
        result.combined_evidence = "\n\n".join(evidence_parts)

        # Run AI analysis on combined evidence if we have any
        if result.combined_evidence.strip():
            result.analysis = run_intelligence_analysis(
                raw_evidence=result.combined_evidence,
                system_prompt=system_prompt,
                command_name="auto-investigate",
                target=target,
                task_instruction=(
                    "Perform a comprehensive security investigation of this target. "
                    "Correlate findings across all data sources (Nmap, web detection, TLS, DNS, "
                    "WHOIS, and vulnerability scans). Identify the most critical risks and provide "
                    "prioritized remediation guidance."
                ),
            )

        return result

    def quick_investigation(
        self,
        target: str,
        system_prompt: str,
    ) -> InvestigationWorkflowResult:
        """Run a quick investigation (Nmap + DNS + TLS only)."""
        result = InvestigationWorkflowResult(target=target)
        evidence_parts: list[str] = []

        # Step 1: Nmap quick scan
        step = WorkflowStep(name="Quick Nmap Scan", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("nmap"):
            stdout, stderr, rc = ToolRunner.run(
                ToolRunner.build_command("nmap", "-F", target),
                timeout=120,
            )
            step.output = stdout
            step.status = "completed" if stdout.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = f"nmap not installed. {install_hint('nmap')}"
        if step.output:
            evidence_parts.append(f"=== NMAP QUICK SCAN ===\n{step.output}")

        # Step 2: DNS
        step = WorkflowStep(name="DNS Check", status="running")
        result.steps.append(step)
        for tool in ("dig", "nslookup", "host"):
            if ToolRunner.is_installed(tool):
                stdout, stderr, rc = ToolRunner.run(
                    ToolRunner.build_command(tool, target),
                    timeout=10,
                )
                step.output = stdout
                step.status = "completed" if stdout.strip() else "failed"
                break
        else:
            step.status = "skipped"
            step.error = "No DNS tool available"
        if step.output:
            evidence_parts.append(f"=== DNS ===\n{step.output}")

        # Step 3: TLS
        step = WorkflowStep(name="TLS Check", status="running")
        result.steps.append(step)
        if ToolRunner.is_installed("openssl"):
            host_part = target.split(":")[0]
            stdout, stderr, rc = ToolRunner.run_shell(
                f"echo | openssl s_client -connect {host_part}:443 -servername {host_part} 2>/dev/null",
                timeout=10,
            )
            step.output = stdout or stderr or ""
            step.status = "completed" if step.output.strip() else "failed"
        else:
            step.status = "skipped"
            step.error = "openssl not installed"
        if step.output:
            evidence_parts.append(f"=== TLS ===\n{step.output}")

        result.combined_evidence = "\n\n".join(evidence_parts)

        if result.combined_evidence.strip():
            result.analysis = run_intelligence_analysis(
                raw_evidence=result.combined_evidence,
                system_prompt=system_prompt,
                command_name="quick-investigate",
                target=target,
                task_instruction="Perform a quick security assessment based on the available evidence.",
            )

        return result
