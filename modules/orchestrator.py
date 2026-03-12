"""Orchestrator — thin coordination layer for Freddy multi-tool workflows."""

from __future__ import annotations

from modules.intelligence_pipeline import AnalysisResult


def run_recon_workflow(target: str, system_prompt: str) -> AnalysisResult:
    """
    Execute the full external reconnaissance workflow against *target*.

    Delegates to commands.recon which collects nmap, whatweb, nikto, openssl,
    dig/nslookup, and whois output, then routes the correlated evidence through
    the intelligence pipeline.
    """
    from commands.recon import run_recon  # local import to avoid circular deps

    return run_recon(target, system_prompt)


def run_host_audit_workflow(system_prompt: str) -> AnalysisResult:
    """
    Execute the comprehensive local host security audit workflow.

    Delegates to commands.host_audit which collects ss, ufw/iptables/nft,
    systemctl, fail2ban, journalctl, sshd_config, ps, df/free, docker ps,
    and SUID/world-writable file data, then routes through the pipeline.
    """
    from commands.host_audit import run_host_audit  # local import

    return run_host_audit(system_prompt)


def run_investigate_workflow(file_path: str, system_prompt: str) -> AnalysisResult:
    """
    Execute a deep investigation of a single artifact (log, config, or output file).

    Delegates to commands.investigate which classifies the artifact, extracts
    threat indicators, and routes accumulated evidence through the pipeline.
    """
    from commands.investigate import run_investigate  # local import

    return run_investigate(file_path, system_prompt)
