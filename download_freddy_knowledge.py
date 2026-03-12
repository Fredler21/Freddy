#!/usr/bin/env python3
"""download_freddy_knowledge.py

Downloads trusted cybersecurity PDF documents from official sources into
Freddy's knowledge folders, then prints a summary of what was fetched.

All sources are:
  - NIST Computer Security Resource Center  (nvlpubs.nist.gov)
  - IETF RFC Editor                         (rfc-editor.org)
  - Wireshark project                       (wireshark.org)

Usage:
    python3 download_freddy_knowledge.py

After downloading, build the Freddy knowledge index:
    python3 freddy.py learn
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Soft dependencies — install if missing
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.exceptions import ConnectionError, HTTPError, Timeout
except ImportError:
    print("[setup] 'requests' not installed. Installing now...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests
    from requests.exceptions import ConnectionError, HTTPError, Timeout

try:
    from tqdm import tqdm as _tqdm_cls
    TQDM_OK = True
except ImportError:
    TQDM_OK = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent
KNOWLEDGE   = BASE_DIR / "knowledge"

CHUNK_SIZE  = 8_192          # bytes per read() call
MAX_RETRIES = 3
RETRY_DELAY = 4              # seconds between retries
REQUEST_TIMEOUT = 60         # seconds per request
USER_AGENT  = "Mozilla/5.0 (compatible; FreddyKnowledgeBot/1.0)"

# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
class Entry(NamedTuple):
    folder:      str    # subfolder under knowledge/
    filename:    str    # saved filename
    url:         str    # download URL
    description: str    # human-readable label


CATALOG: list[Entry] = [

    # ── Nmap / Security Testing ───────────────────────────────────────────
    Entry(
        "nmap",
        "nist_sp800-115_security_testing.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
        "NIST SP 800-115 — Technical Guide to Information Security Testing & Assessment",
    ),

    # ── Wireshark ─────────────────────────────────────────────────────────
    Entry(
        "wireshark",
        "wireshark_users_guide.pdf",
        "https://www.wireshark.org/download/docs/wireshark-users-guide.pdf",
        "Official Wireshark User Guide",
    ),

    # ── Linux ─────────────────────────────────────────────────────────────
    Entry(
        "linux",
        "nist_sp800-123_server_security.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
        "NIST SP 800-123 — Guide to General Server Security",
    ),

    # ── Ubuntu ────────────────────────────────────────────────────────────
    Entry(
        "ubuntu",
        "nist_sp800-123_server_security.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
        "NIST SP 800-123 — Guide to General Server Security (Ubuntu/Linux applicable)",
    ),

    # ── Networking ────────────────────────────────────────────────────────
    Entry(
        "networking",
        "ietf_rfc793_tcp_specification.pdf",
        "https://www.rfc-editor.org/rfc/pdfrfc/rfc793.txt.pdf",
        "RFC 793 — Transmission Control Protocol (TCP) Specification",
    ),
    Entry(
        "networking",
        "ietf_rfc1035_dns_specification.pdf",
        "https://www.rfc-editor.org/rfc/pdfrfc/rfc1035.txt.pdf",
        "RFC 1035 — Domain Names: Implementation and Specification",
    ),
    Entry(
        "networking",
        "ietf_rfc2616_http11.pdf",
        "https://www.rfc-editor.org/rfc/pdfrfc/rfc2616.txt.pdf",
        "RFC 2616 — Hypertext Transfer Protocol 1.1",
    ),
    Entry(
        "networking",
        "nist_sp800-41r1_firewall_guidelines.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41rev1.pdf",
        "NIST SP 800-41 Rev 1 — Guidelines on Firewalls and Firewall Policy",
    ),

    # ── Web Security ──────────────────────────────────────────────────────
    Entry(
        "web_security",
        "nist_sp800-44v2_web_server_security.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-44ver2.pdf",
        "NIST SP 800-44v2 — Guidelines on Securing Public Web Servers",
    ),

    # ── Log Analysis ──────────────────────────────────────────────────────
    Entry(
        "log_analysis",
        "nist_sp800-92_log_management.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf",
        "NIST SP 800-92 — Guide to Computer Security Log Management",
    ),

    # ── Incident Response ─────────────────────────────────────────────────
    Entry(
        "incident_response",
        "nist_sp800-61r2_incident_handling.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        "NIST SP 800-61r2 — Computer Security Incident Handling Guide",
    ),
    Entry(
        "incident_response",
        "nist_sp800-86_forensics_integration.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-86.pdf",
        "NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response",
    ),

    # ── Threat Detection ──────────────────────────────────────────────────
    Entry(
        "threat_detection",
        "nist_sp800-94_intrusion_detection.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf",
        "NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems (IDPS)",
    ),
    Entry(
        "threat_detection",
        "nist_sp800-83r1_malware_prevention.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-83r1.pdf",
        "NIST SP 800-83r1 — Guide to Malware Incident Prevention and Handling",
    ),
    Entry(
        "threat_detection",
        "nist_sp800-150_threat_intelligence.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf",
        "NIST SP 800-150 — Guide to Cyber Threat Information Sharing",
    ),

    # ── Hardening ─────────────────────────────────────────────────────────
    Entry(
        "hardening",
        "nist_sp800-128_configuration_management.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf",
        "NIST SP 800-128 — Security-Focused Configuration Management of Information Systems",
    ),
    Entry(
        "hardening",
        "nist_sp800-77r1_ipsec_vpn.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf",
        "NIST SP 800-77r1 — Guide to IPsec VPNs (VPN hardening and tunneling)",
    ),

    # ── Vulnerabilities ───────────────────────────────────────────────────
    Entry(
        "vulnerabilities",
        "nist_sp800-40r4_patch_management.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf",
        "NIST SP 800-40r4 — Guide to Enterprise Patch Management Planning",
    ),
    Entry(
        "vulnerabilities",
        "nist_sp800-30r1_risk_assessment.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-30r1.pdf",
        "NIST SP 800-30r1 — Guide for Conducting Risk Assessments",
    ),
]

# Folders to ensure exist (including new ones not yet in the repo)
REQUIRED_FOLDERS = [
    "nmap", "wireshark", "linux", "ubuntu", "networking",
    "web_security", "log_analysis", "incident_response",
    "threat_detection", "hardening", "vulnerabilities",
    "security_basics", "nikto", "gobuster", "ffuf", "tcpdump",
    "metasploit", "burpsuite", "hydra", "john_the_ripper",
    "aircrack", "dns_tools",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_folders() -> None:
    """Create all required knowledge subdirectories."""
    for name in REQUIRED_FOLDERS:
        folder = KNOWLEDGE / name
        folder.mkdir(parents=True, exist_ok=True)
    KNOWLEDGE.mkdir(parents=True, exist_ok=True)
    print(f"[folders] All knowledge subdirectories verified under {KNOWLEDGE}\n")


def _is_valid_pdf(path: Path) -> bool:
    """Return True if the file exists, is non-empty, and starts with the PDF magic bytes."""
    try:
        if path.stat().st_size < 128:
            return False
        with path.open("rb") as fh:
            return fh.read(5) == b"%PDF-"
    except OSError:
        return False


def _download_with_progress(url: str, dest: Path, label: str) -> bool:
    """
    Stream-download *url* to *dest*, showing a tqdm bar if available.

    Returns True on success, False on any recoverable error.
    """
    headers = {"User-Agent": USER_AGENT}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, stream=True, timeout=REQUEST_TIMEOUT, headers=headers)
            response.raise_for_status()

            total = int(response.headers.get("content-length", 0))
            tmp = dest.with_suffix(".tmp")

            if TQDM_OK:
                bar = _tqdm_cls(
                    total=total or None,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc=f"  {dest.name}",
                    leave=False,
                )
            else:
                bar = None

            with tmp.open("wb") as fh:
                received = 0
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    if chunk:
                        fh.write(chunk)
                        received += len(chunk)
                        if bar:
                            bar.update(len(chunk))
                        elif total:
                            pct = int(received / total * 100)
                            print(f"\r  {dest.name}: {pct}%", end="", flush=True)

            if bar:
                bar.close()
            elif total:
                print()  # newline after inline progress

            # Validate before promoting to final path
            if not _is_valid_pdf(tmp):
                tmp.unlink(missing_ok=True)
                print(f"  [!] Downloaded file is not a valid PDF — skipping.")
                return False

            tmp.rename(dest)
            return True

        except HTTPError as exc:
            code = exc.response.status_code if exc.response else "?"
            print(f"  [!] HTTP {code} for {url}")
            if code in (403, 404, 410):
                return False   # non-retriable
        except (ConnectionError, Timeout) as exc:
            print(f"  [!] Network error (attempt {attempt}/{MAX_RETRIES}): {exc}")
        except Exception as exc:
            print(f"  [!] Unexpected error: {exc}")
            return False

        if attempt < MAX_RETRIES:
            print(f"  [~] Retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 62)
    print("  Freddy Cybersecurity Knowledge Downloader")
    print("  Sources: NIST CSRC · IETF RFC Editor · Wireshark")
    print("=" * 62)
    print()

    ensure_folders()

    total   = len(CATALOG)
    skipped = 0
    ok      = 0
    failed: list[str] = []

    for i, entry in enumerate(CATALOG, start=1):
        dest_dir  = KNOWLEDGE / entry.folder
        dest_file = dest_dir / entry.filename

        print(f"[{i:02}/{total}] {entry.description}")

        if dest_file.exists() and _is_valid_pdf(dest_file):
            size_kb = dest_file.stat().st_size // 1024
            print(f"  [skip] Already exists ({size_kb} KB) — {dest_file.name}\n")
            skipped += 1
            continue

        print(f"  [dl]   {entry.url}")
        success = _download_with_progress(entry.url, dest_file, entry.description)

        if success:
            size_kb = dest_file.stat().st_size // 1024
            print(f"  [ok]   Saved to {dest_file.relative_to(BASE_DIR)}  ({size_kb} KB)\n")
            ok += 1
        else:
            print(f"  [fail] Could not download — check URL or network connection.\n")
            failed.append(entry.filename)

    # ── Summary ─────────────────────────────────────────────────────────────
    print("=" * 62)
    print(f"  Downloaded : {ok}")
    print(f"  Skipped    : {skipped}  (already present)")
    print(f"  Failed     : {len(failed)}")
    if failed:
        print("\n  Failed files (update URLs in CATALOG if needed):")
        for name in failed:
            print(f"    - {name}")
    print("=" * 62)
    print()

    if ok + skipped > 0:
        print("Cybersecurity knowledge library successfully built.")
        print()
        print("Next step — index everything into Freddy's vector store:")
        print()
        print("    python3 freddy.py learn")
        print()
    else:
        print("[!] No files were downloaded. Check your internet connection")
        print("    and verify the URLs in the CATALOG at the top of this script.")
        sys.exit(1)


if __name__ == "__main__":
    main()
