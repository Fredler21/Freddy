"""Recon command — multi-tool external reconnaissance workflow."""

from __future__ import annotations

import socket

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.tool_runner import ToolRunner


def run_recon(target: str, system_prompt: str) -> AnalysisResult:
    """
    Run a full external reconnaissance workflow against a target.

    Collects output from nmap, whatweb, nikto, openssl, dig/nslookup/host,
    and whois then feeds the correlated evidence to the intelligence pipeline
    for a consolidated analyst report.
    """
    formatter = OutputFormatter()
    sections: list[str] = []

    # Resolve target to hostname for DNS stages, IP for scan stages
    host = target.split(":")[0].split("/")[0]

    # --- 1. Nmap service + script scan ---
    if ToolRunner.is_installed("nmap"):
        formatter.print_info(f"[Recon] Nmap service scan → {host}")
        cmd = ["nmap", "-sV", "-sC", "--open", "-T4", host]
        stdout, stderr, rc = ToolRunner.run(cmd, timeout=180)
        out = (stdout or stderr or "").strip()
        if out:
            sections.append(f"=== NMAP SERVICE SCAN (-sV -sC) ===\n{out}")
    else:
        sections.append("=== NMAP SERVICE SCAN ===\n[nmap not found — skipped]")

    # --- 2. WhatWeb technology fingerprinting ---
    url_target = target if target.startswith(("http://", "https://")) else f"http://{host}"
    if ToolRunner.is_installed("whatweb"):
        formatter.print_info(f"[Recon] WhatWeb fingerprint → {url_target}")
        stdout, stderr, _ = ToolRunner.run(["whatweb", "--no-errors", "-a", "3", url_target], timeout=60)
        out = (stdout or stderr or "").strip()
        if out:
            sections.append(f"=== WHATWEB FINGERPRINT ===\n{out}")
    else:
        sections.append("=== WHATWEB FINGERPRINT ===\n[whatweb not found — skipped]")

    # --- 3. Nikto web vulnerability scan ---
    if ToolRunner.is_installed("nikto"):
        formatter.print_info(f"[Recon] Nikto web scan → {url_target}")
        stdout, stderr, _ = ToolRunner.run(["nikto", "-h", url_target, "-nointeractive"], timeout=120)
        out = (stdout or stderr or "").strip()
        if out:
            sections.append(f"=== NIKTO WEB SCAN ===\n{out}")
    else:
        sections.append("=== NIKTO WEB SCAN ===\n[nikto not found — skipped]")

    # --- 4. TLS / certificate inspection ---
    tls_host = host
    tls_port = "443"
    if ":" in target.split("/")[0]:
        parts = target.split("/")[0].split(":")
        tls_host = parts[0]
        tls_port = parts[1] if len(parts) > 1 else "443"
    if ToolRunner.is_installed("openssl"):
        formatter.print_info(f"[Recon] TLS check → {tls_host}:{tls_port}")
        # Use echo Q | openssl … so the client sends a close_notify and exits cleanly
        connect_str = f"{tls_host}:{tls_port}"
        stdout, stderr, _ = ToolRunner.run_shell(
            f"echo Q | openssl s_client -connect {connect_str} -brief 2>&1",
            timeout=20,
        )
        out = (stdout or stderr or "").strip()
        if out:
            sections.append(f"=== TLS / CERTIFICATE ({tls_host}:{tls_port}) ===\n{out}")
        # Protocol downgrade checks
        for proto_flag, label in [("-tls1", "TLS 1.0"), ("-tls1_1", "TLS 1.1")]:
            stdout2, _, rc2 = ToolRunner.run_shell(
                f"echo Q | openssl s_client -connect {connect_str} {proto_flag} 2>&1",
                timeout=10,
            )
            status = "ACCEPTED" if rc2 == 0 else "REJECTED"
            sections.append(f"=== TLS DOWNGRADE PROBE ({label}) ===\nResult: {status}\n{(stdout2 or '').strip()[:400]}")
    else:
        sections.append("=== TLS / CERTIFICATE ===\n[openssl not found — skipped]")

    # --- 5. DNS posture ---
    if ToolRunner.is_installed("dig"):
        formatter.print_info(f"[Recon] DNS posture → {host}")
        for record_type in ("A", "MX", "TXT", "AAAA", "NS"):
            stdout, _, _ = ToolRunner.run(["dig", host, record_type, "+short"], timeout=15)
            if stdout.strip():
                sections.append(f"=== DNS {record_type} RECORDS ({host}) ===\n{stdout.strip()}")
        # SPF / DMARC explicitly
        for txt_query in (f"{host}", f"_dmarc.{host}"):
            stdout, _, _ = ToolRunner.run(["dig", txt_query, "TXT", "+short"], timeout=10)
            if stdout.strip():
                sections.append(f"=== DNS TXT ({txt_query}) ===\n{stdout.strip()}")
    elif ToolRunner.is_installed("nslookup"):
        formatter.print_info(f"[Recon] nslookup → {host}")
        stdout, _, _ = ToolRunner.run(["nslookup", host], timeout=15)
        if stdout.strip():
            sections.append(f"=== NSLOOKUP ({host}) ===\n{stdout.strip()}")

    # --- 6. WHOIS ---
    if ToolRunner.is_installed("whois"):
        formatter.print_info(f"[Recon] WHOIS → {host}")
        stdout, _, _ = ToolRunner.run(["whois", host], timeout=30)
        out = (stdout or "").strip()
        if out:
            # Truncate to first 80 lines to avoid noise
            whois_lines = out.splitlines()[:80]
            sections.append(f"=== WHOIS ({host}) ===\n" + "\n".join(whois_lines))

    if not sections:
        return AnalysisResult(
            report="[!] No recon tools were available or produced output. Install nmap, nikto, whatweb, and whois.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    raw_evidence = "\n\n".join(sections)

    return run_intelligence_analysis(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        command_name="recon",
        target=host,
        task_instruction=(
            f"This is a full external reconnaissance report for target '{host}'. "
            "Correlate findings across ALL tools above. Identify the complete attack surface: "
            "exposed services, technology stack, open ports, TLS weaknesses, DNS misconfigurations, "
            "and WHOIS-level intelligence. Link related findings across tools (e.g., an old Apache "
            "version seen in both nmap and whatweb). Assign a combined SEVERITY and provide a "
            "prioritized remediation plan addressing the highest-risk exposures first."
        ),
    )
