"""Network analyzer module — parses Nmap and ss output for quick local checks."""

import re


def parse_open_ports(ss_output: str) -> list[dict]:
    """Parse ss -tulpn output into structured port info."""
    ports = []
    for line in ss_output.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 5:
            ports.append({
                "protocol": parts[0],
                "state": parts[1],
                "local_address": parts[4],
            })
    return ports


def parse_nmap_ports(nmap_output: str) -> list[dict]:
    """Extract port/service pairs from Nmap output."""
    port_re = re.compile(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)")
    results = []
    for match in port_re.finditer(nmap_output):
        results.append({
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "state": match.group(3),
            "service": match.group(4).strip(),
        })
    return results
