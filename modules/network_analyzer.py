"""Network Analyzer Module — interprets network tool outputs."""

import re
from typing import List, Dict


class NetworkAnalyzer:
    """Analyzes network scans and service outputs."""

    @staticmethod
    def extract_ports(nmap_output: str) -> List[Dict[str, str]]:
        """Extract open ports and services from nmap output."""
        ports = []
        lines = nmap_output.split("\n")
        for line in lines:
            if "open" in line.lower():
                match = re.search(r"(\d+)/(\w+)\s+(\w+)\s+(.+)", line)
                if match:
                    ports.append({
                        "port": match.group(1),
                        "protocol": match.group(2),
                        "state": match.group(3),
                        "service": match.group(4),
                    })
        return ports

    @staticmethod
    def extract_listening_ports(ss_output: str) -> List[Dict[str, str]]:
        """Extract listening ports from ss output."""
        ports = []
        lines = ss_output.split("\n")
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 5:
                ports.append({
                    "protocol": parts[0],
                    "recv_q": parts[1],
                    "send_q": parts[2],
                    "address": parts[3],
                    "state": parts[4],
                })
        return ports

    @staticmethod
    def is_port_internal(port: int) -> bool:
        """Determine if a port should be internal."""
        internal_ports = [22, 25, 111, 139, 445, 3306, 5432, 6379, 27017]
        return port in internal_ports


# Backward compatibility functions
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
