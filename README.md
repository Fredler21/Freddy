# 🛡️ Freddy, AI-Powered Cybersecurity Terminal Copilot

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-blue) ![Privacy](https://img.shields.io/badge/Privacy-red) ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-black?logo=linux) ![Kali Linux](https://img.shields.io/badge/Kali%20Linux-557C94?logo=kalilinux&logoColor=white) ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white) ![License](https://img.shields.io/badge/License-Proprietary-red)

> **Your personal SOC analyst, right in the terminal.**

Freddy is an enterprise-grade AI cybersecurity copilot that transforms raw security data into actionable intelligence. Built for defenders, it integrates real-time tool execution, MITRE ATT&CK mapping, IOC extraction, threat intelligence feeds, SIEM-style correlation, incident timeline reconstruction, and AI-driven analysis into a single command-line platform.

Under the hood, Freddy runs a multi-stage intelligence pipeline: deterministic rule checks catch known patterns, a local knowledge engine retrieves relevant guidance from 40+ indexed NIST, OWASP, and RFC documents, and a SOC enrichment layer maps findings to ATT&CK techniques, extracts indicators of compromise, correlates events across sources, and scores your security posture, all before the AI model even sees the data. The result is analysis that's structured, repeatable, and backed by real evidence.

Whether you're triaging an incident, auditing a server, analyzing logs, or investigating a target, Freddy handles the heavy lifting so you can focus on decisions, not data parsing.

**Freddy is for authorized defensive security work only.**

---

## 🛡️ What This AI Is For

Freddy is built to help defenders understand security data faster and take action with confidence.

- 🛡️ Explain raw security output in plain language (Nmap, logs, TLS, DNS, web scans)
- 🚨 Detect likely risks and misconfigurations before they are missed
- 📊 Prioritize issues by severity so you fix the most important problems first
- 🧠 Use local cybersecurity knowledge during analysis (NIST, RFCs, OWASP, and more)
- 🕒 Compare current findings with prior scans to catch recurring problems
- ✅ Give step-by-step remediation and verification commands
- 🗺️ Map findings to MITRE ATT&CK techniques and tactics
- 🔍 Extract and check Indicators of Compromise against threat intel feeds
- ⏱️ Reconstruct incident timelines from log evidence
- 📡 Correlate findings across sources with SIEM-style rules
- 📈 Score security posture with a 0–100 grading system
- 📝 Generate professional exportable security reports

---

## 🎯 What Freddy Can Do

| Category | What It Does |
|---|---|
| 🔎 **Scan & Recon** | Run Nmap port scans, full multi-tool reconnaissance, automated target profiling to discover open ports, running services, OS fingerprints, and exposed attack surface |
| 📋 **Log Analysis** | Parse auth.log, Apache/Nginx web logs, syslog files to detect brute-force attempts, failed logins, intrusion indicators, and suspicious access patterns |
| 🖥️ **System Auditing** | Audit local listening ports, firewall rules (UFW/iptables), SSH configuration, user accounts, sudo privileges, and active service exposure |
| 📄 **File Analysis** | Analyze any saved security tool output like Nmap results, scan reports, packet captures, config dumps through the full enrichment pipeline |
| 🌐 **Web Security** | Inspect HTTP response headers, detect missing security headers, identify web technologies, check for known web vulnerabilities with Nikto |
| 🔒 **TLS/SSL Inspection** | Evaluate certificates, cipher suites, protocol versions, expiration dates, and weak configurations using OpenSSL |
| 🌍 **DNS Analysis** | Query DNS records (A, AAAA, MX, NS, TXT, CNAME), detect misconfigurations, check for dangling records and zone transfer risks |
| 📇 **WHOIS Lookups** | Retrieve domain registration details, registrar info, creation/expiration dates, and nameserver configuration |
| 🗺️ **MITRE ATT&CK Mapping** | Automatically map every finding to ATT&CK technique IDs and tactics, 25+ patterns across Credential Access, Initial Access, Discovery, Persistence, Lateral Movement, and more |
| 🔍 **IOC Extraction** | Pull IP addresses, domains, URLs, email addresses, file hashes (MD5/SHA1/SHA256), CVE identifiers, suspicious file paths, and user agents from any evidence |
| 🌐 **Threat Intelligence** | Check extracted IOCs against AbuseIPDB, VirusTotal, and AlienVault OTX to get abuse scores, detection ratios, and reputation data |
| ⏱️ **Incident Timeline** | Reconstruct chronological attack timelines from log timestamps and classify events by phase (recon → initial access → execution → persistence → lateral movement → exfiltration) |
| 📡 **SIEM Correlation** | Detect cross-source attack patterns with 7 correlation rules: brute-force chains, scan-to-exploit sequences, multi-source IP activity, service exposure chains, and more |
| 🤖 **Auto Investigation** | Chain 6 recon tools (Nmap + web check + TLS + DNS + WHOIS + Nikto) into a single command. All evidence feeds through the full SOC pipeline automatically |
| 📊 **Posture Scoring** | Calculate a 0–100 security posture score with letter grade (A–F) based on rule findings, MITRE mappings, IOC counts, and correlation results |
| 📝 **Report Generation** | Export professional security reports in Markdown or JSON including executive summary, ATT&CK mappings, IOCs, timeline, correlations, posture score, and remediation steps |
| 🎓 **Security Mentor** | Get educational learning notes alongside findings: plain-language explanations, real-world breach context, and references to NIST, CIS Benchmarks, MITRE ATT&CK, and OWASP |
| 🎨 **Visualization** | See ASCII attack timeline charts, severity distribution bars, MITRE ATT&CK tactic matrices, posture gauges, IP activity maps, and attack surface diagrams in the terminal |
| 🧠 **Knowledge Search** | Semantic search across 40+ indexed NIST, RFC, and OWASP documents. Ask questions in natural language and get relevant cybersecurity guidance |
| 🗂️ **Scan Memory** | SQLite history that remembers every scan, tracks targets over time, detects recurring vulnerabilities, correlates findings across weeks and months |

---

## 🚀 How to Use Freddy

Once installed, here are the most common things you'll do with Freddy:

### 🔎 Scan a target

```bash
python3 freddy.py scan 192.168.1.10
```

Freddy runs Nmap, applies security rules, maps findings to MITRE ATT&CK, extracts IOCs, scores your posture, and generates a full AI-powered analysis, all in one command.

### 📄 Analyze a file

```bash
python3 freddy.py analyze samples/sample_nmap.txt
python3 freddy.py logs /var/log/auth.log
```

Feed Freddy any security tool output or log file. It runs the full SOC enrichment pipeline and produces a structured defensive report.

### 🤖 Run a full automated investigation

```bash
python3 freddy.py auto-investigate example.com
```

This chains 6 tools together (Nmap + web check + TLS + DNS + WHOIS + Nikto), collects all evidence, and runs the complete analysis pipeline. Use `--quick` for a faster 3-tool version.

### 🌐 Check web, TLS, DNS, and WHOIS

```bash
python3 freddy.py webcheck example.com
python3 freddy.py tlscheck example.com
python3 freddy.py dnscheck example.com
python3 freddy.py whois example.com
```

### 🖥️ Audit your own machine

```bash
python3 freddy.py ports       # What's listening?
python3 freddy.py audit       # Full system security audit
```

### 🔍 Extract IOCs and check threat intel

```bash
python3 freddy.py ioc-extract samples/sample_log.txt        # Extract IPs, domains, hashes, CVEs
python3 freddy.py threat-intel 45.33.32.156                  # Check IP against threat feeds
python3 freddy.py threat-intel suspicious-domain.com         # Check domain
```

### ⏱️ Build an incident timeline

```bash
python3 freddy.py timeline samples/sample_log.txt
```

### 📊 Get a security posture score

```bash
python3 freddy.py posture samples/sample_nmap.txt
```

### 📝 Generate a professional report

```bash
python3 freddy.py report samples/sample_nmap.txt                  # Markdown report
python3 freddy.py report samples/sample_log.txt --format json     # JSON report
```

Reports are saved to `data/reports/`.

### 🧠 Search the knowledge base

```bash
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py knowledge-search "How do I detect SQL injection in logs?"
```

### 🕒 View scan history

```bash
python3 freddy.py history
python3 freddy.py history --target example.com
```

### 💡 Tips

- Add `--yes` to skip confirmation prompts: `python3 freddy.py scan 192.168.1.10 --yes`
- Add `--no-banner` to hide the startup banner
- MITRE ATT&CK mapping, IOC extraction, SIEM correlation, posture scoring, and learning notes run **automatically** on every analysis, no extra flags needed
- For threat intel, optionally set `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` environment variables (AlienVault OTX works free without a key)
- Use `python3 freddy.py walkthrough` for a guided interactive menu

---

## ⚡ Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Fredler21/Freddy.git
cd Freddy

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt
```

### 2. Build the knowledge index

```bash
python3 freddy.py learn
```

This indexes all documents in `knowledge/` and `vulnerabilities/` into a local vector database for retrieval during analysis.

### 3. Run Freddy

```bash
python3 freddy.py                  # Interactive welcome menu
python3 freddy.py --help           # See all commands
python3 freddy.py walkthrough      # Guided step-by-step menu
```

---

## 📋 All Commands

### 🔎 Scanning & Reconnaissance

```bash
# Scan a target with Nmap
python3 freddy.py scan 192.168.1.10
python3 freddy.py scan example.com

# Full reconnaissance (multiple tools)
python3 freddy.py recon example.com

# Automated multi-tool investigation (Nmap + TLS + DNS + WHOIS + web + Nikto)
python3 freddy.py auto-investigate example.com
python3 freddy.py auto-investigate example.com --quick    # Fast 3-tool version
```

### 🌐 Web, TLS, DNS & WHOIS

```bash
python3 freddy.py webcheck example.com       # HTTP headers, technologies, vulns
python3 freddy.py tlscheck example.com       # Certificate + cipher analysis
python3 freddy.py dnscheck example.com       # DNS record analysis
python3 freddy.py whois example.com          # Domain registration info
```

### 🖥️ System Auditing (Linux)

```bash
python3 freddy.py ports                      # What's listening on this machine?
python3 freddy.py audit                      # Full system security audit
python3 freddy.py host-audit                 # Host-level checks
```

### 📄 File & Log Analysis

```bash
# Analyze any security tool output saved to a file
python3 freddy.py analyze samples/sample_nmap.txt
python3 freddy.py analyze path/to/nmap_output.txt

# Analyze log files (auth.log, web logs, syslog)
python3 freddy.py logs samples/sample_log.txt
python3 freddy.py logs /var/log/auth.log

# Investigate a file with contextual analysis
python3 freddy.py investigate path/to/evidence.txt
```

### 🔬 SOC-Grade Commands

```bash
# Extract Indicators of Compromise from any evidence file
python3 freddy.py ioc-extract samples/sample_log.txt

# Check an IP or domain against threat intelligence feeds
python3 freddy.py threat-intel 45.33.32.156
python3 freddy.py threat-intel suspicious-domain.com

# Reconstruct incident timeline from logs
python3 freddy.py timeline samples/sample_log.txt

# View security posture score for evidence
python3 freddy.py posture samples/sample_nmap.txt

# Generate a professional security report
python3 freddy.py report samples/sample_nmap.txt
python3 freddy.py report samples/sample_log.txt --format json
```

### 📚 Knowledge & History

```bash
# Build or rebuild the knowledge index
python3 freddy.py learn

# Search the local cybersecurity knowledge base
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py knowledge-search "How do I detect SQL injection in logs?"

# View scan history
python3 freddy.py history
python3 freddy.py history --target example.com

# View memory database statistics
python3 freddy.py memory-stats

# Interactive guided menu
python3 freddy.py walkthrough
```

### 🏷️ Command Flags

| Flag | What it does |
|---|---|
| `--yes` or `-y` | Skip confirmation prompts (useful for scripts) |
| `--no-banner` | Hide the startup banner |
| `--quick` | Use fast mode (for `auto-investigate`) |
| `--format json` | Output as JSON (for `report`) |

Examples:

```bash
python3 freddy.py scan 192.168.1.10 --yes          # No confirmation prompt
python3 freddy.py --no-banner scan 192.168.1.10     # No banner
python3 freddy.py report evidence.txt --format json  # JSON report
```

---

## 🔬 SOC-Grade Features (Detail)

These features run **automatically** on every analysis. They are also available as standalone commands.

### 🗺️ MITRE ATT&CK Mapping

Every analysis maps detected behaviors to the MITRE ATT&CK framework. Freddy identifies 25+ techniques across 12 tactics:

- **Credential Access**: T1110 Brute Force, T1003 OS Credential Dumping
- **Initial Access**: T1190 Exploit Public-Facing Application, T1078 Valid Accounts
- **Discovery**: T1046 Network Service Scanning, T1087 Account Discovery
- **Persistence**: T1098 Account Manipulation, T1136 Create Account
- **Privilege Escalation**: T1548 Abuse Elevation Control, T1068 Exploitation for Privilege Escalation
- **Defense Evasion**: T1070 Indicator Removal, T1562 Impair Defenses
- **Lateral Movement**: T1021 Remote Services, T1563 Remote Service Session Hijacking
- **Execution**: T1059 Command and Scripting Interpreter
- And more across Exfiltration, Collection, Impact, and Command & Control

Mappings appear in analysis output with technique IDs, tactic names, and confidence levels (HIGH/MEDIUM/LOW).

### 🔍 IOC Extraction

Freddy extracts 9 types of Indicators of Compromise from any evidence:

| IOC Type | Example |
|---|---|
| IP Addresses | `45.33.32.156`, `192.168.1.100` |
| Domains | `malicious-domain.com` |
| URLs | `http://evil.com/payload.sh` |
| Email Addresses | `attacker@evil.com` |
| File Hashes | MD5, SHA1, SHA256 (auto-labeled) |
| CVE Identifiers | `CVE-2021-44228` |
| Suspicious File Paths | `/tmp/.hidden`, `/dev/shm/payload` |
| User Agents | Unusual or known-malicious user agent strings |
| Network Ports | Open ports detected in evidence |

Private IPs and benign domains (localhost, ubuntu.com, etc.) are filtered automatically.

```bash
python3 freddy.py ioc-extract samples/sample_log.txt
```

### 🌐 Threat Intelligence Lookup

Check extracted IOCs against external threat feeds:

| Source | API Key Required | Environment Variable | What It Returns |
|---|---|---|---|
| AbuseIPDB | Yes | `ABUSEIPDB_API_KEY` | Abuse confidence score, reports count, country |
| VirusTotal | Yes | `VIRUSTOTAL_API_KEY` | Detection ratio, malicious/suspicious flags |
| AlienVault OTX | No | N/A | Pulse count, reputation data |

```bash
# Set API keys (optional, AlienVault OTX works without any key)
export ABUSEIPDB_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"

# Check an IP
python3 freddy.py threat-intel 45.33.32.156

# Check a domain
python3 freddy.py threat-intel suspicious-domain.com
```

Threat intel runs automatically after every analysis too. It checks the IOCs extracted from evidence.

### ⏱️ Incident Timeline Reconstruction

Freddy parses timestamps from log evidence and builds a chronological attack timeline:

- Supports 4 timestamp formats: syslog, ISO 8601, Apache, and generic HH:MM:SS
- Classifies events by type: authentication, network, web, system, malware, privilege escalation
- Groups events into attack phases: reconnaissance → initial access → execution → persistence → lateral movement → exfiltration

```bash
python3 freddy.py timeline samples/sample_log.txt
```

### 📡 SIEM-Style Correlation

Seven correlation rules detect cross-source attack patterns:

| Rule | What It Detects |
|---|---|
| Brute Force Chain | Failed login attempts followed by successful login from same IP |
| Multi-Source IP | Same IP appearing across scan, log, and web evidence |
| Scan to Exploit | Port scan followed by service exploitation attempt |
| Auth to Lateral | Authentication success followed by lateral movement indicators |
| Service Exposure Chain | 3+ critical services exposed simultaneously (SSH + MySQL + Redis, etc.) |
| Log-Web Overlap | Same indicators found in both log and web evidence |
| Timeline Patterns | Rapid sequential events suggesting automated attack tools |

### 🤖 Automated Investigation

Chain multiple reconnaissance tools into a single command. Freddy runs each tool, collects all evidence, and passes it through the full enrichment pipeline:

**Full investigation** (6 tools):
1. Nmap port scan
2. Web technology check (whatweb/curl)
3. TLS/SSL certificate check (openssl)
4. DNS record lookup (dig/nslookup/host)
5. WHOIS domain lookup
6. Nikto web vulnerability scan

**Quick investigation** (3 tools):
1. Nmap fast scan (-F)
2. DNS lookup
3. TLS check

```bash
python3 freddy.py auto-investigate example.com          # Full
python3 freddy.py auto-investigate example.com --quick   # Quick
```

### 📊 Security Posture Scoring

Every analysis receives a 0–100 score with a letter grade:

| Grade | Score | Meaning |
|---|---|---|
| A | 90–100 | Strong security posture |
| B | 80–89 | Good with minor issues |
| C | 70–79 | Moderate risk, action needed |
| D | 60–69 | Significant risk |
| F | 0–59 | Critical, immediate action required |

Penalty weights: CRITICAL (−15), HIGH (−10), MEDIUM (−5), LOW (−2). Score factors include rule findings, MITRE ATT&CK mappings, IOC counts, and correlation findings.

```bash
python3 freddy.py posture samples/sample_nmap.txt
```

### 🎓 Security Mentor

Alongside findings, Freddy adds educational learning notes covering:

- SSH exposure, brute force attacks, weak TLS, open ports
- Firewall configuration, admin endpoint exposure, missing headers
- Container security, sudo misuse, port scanning, DNS issues, log analysis

Each note includes a plain-language explanation, real-world context (e.g., "The 2017 Equifax breach exploited..."), and references to NIST, CIS Benchmarks, MITRE ATT&CK, and OWASP documentation.

### 📝 Professional Report Generation

Generate exportable security reports saved to `data/reports/`:

```bash
# Markdown report (default)
python3 freddy.py report samples/sample_nmap.txt

# JSON report
python3 freddy.py report samples/sample_log.txt --format json
```

Reports include:
- Executive summary
- MITRE ATT&CK technique mappings
- Extracted IOCs with counts
- Incident timeline
- SIEM correlation findings
- Security posture score and grade
- Learning notes and references
- Step-by-step remediation

### 🎨 Security Visualization

Terminal-based ASCII visualizations render during analysis:

- **Attack Timeline Chart:** chronological event bar chart
- **Severity Distribution:** bar chart of finding severities
- **IP Activity Map:** which IPs are doing what
- **Attack Surface Map:** exposed services and entry points
- **Posture Gauge:** visual 0–100 score meter
- **MITRE ATT&CK Matrix:** tactic/technique grid
- **Connection Graph:** relationships between entities

---

## ⚙️ How Analysis Works

Every analysis command (`scan`, `logs`, `audit`, `analyze`, etc.) runs this pipeline:

```
1. Collect raw evidence (tool output or file contents)
2. Run deterministic rule engine (port checks, brute-force patterns, etc.)
3. Retrieve matching knowledge from local vector database
4. Retrieve prior scan history for the same target
5. SOC Enrichment Pipeline:
   ├── Map evidence to MITRE ATT&CK techniques
   ├── Extract Indicators of Compromise
   ├── Reconstruct incident timeline from timestamps
   ├── Correlate findings across sources (SIEM rules)
   ├── Calculate security posture score (0–100)
   └── Generate educational learning notes
6. Send enriched payload to AI model (Claude)
7. Render output with visualizations
8. Check IOCs against threat intelligence feeds
9. Save findings, raw output, and metadata to memory
```

---

## 🏗️ Architecture

```text
📥 Security tools, logs, and scan results
                  |
                  v
🖥️ Freddy CLI (scan, recon, audit, investigate, analyze, auto-investigate)
                  |
                  v
🧩 Pre-AI Intelligence Layer
   ├── 📏 Rule Engine (deterministic checks)
   ├── 📚 Knowledge Retrieval Engine (local indexed docs)
   ├── 🛠️ Vulnerability Intelligence Library
   └── 🗂️ Memory Engine (history + correlation)
                  |
                  v
🔬 SOC Enrichment Pipeline
   ├── 🗺️ MITRE ATT&CK Mapper (technique identification)
   ├── 🔍 IOC Extractor (IPs, domains, hashes, CVEs)
   ├── ⏱️ Timeline Reconstructor (chronological events)
   ├── 📡 SIEM Correlator (cross-source patterns)
   ├── 📊 Posture Scorer (0-100 security grade)
   └── 🎓 Security Mentor (learning notes)
                  |
                  v
🤖 AI Analysis Engine (enriched with SOC context)
                  |
                  v
🌐 Threat Intelligence (AbuseIPDB, VirusTotal, AlienVault OTX)
                  |
                  v
📄 Structured Defensive Report
   ├── Executive summary + posture score
   ├── MITRE ATT&CK mappings
   ├── Indicators of Compromise
   ├── Incident timeline
   ├── Confirmed and suspected findings
   ├── Severity + confidence
   ├── Root cause
   ├── Remediation + verification steps
   └── Security learning notes
```

---

## 📚 Knowledge Base

### What's included

Freddy loads cybersecurity reference material from two folders:

- `knowledge/` broad defensive guidance (Linux security, SSH hardening, web security, incident response, network protocols, and more)
- `vulnerabilities/` focused vulnerability intelligence (SSH exposure, weak TLS, Redis exposure, missing security headers, open ports)

Documents are chunked, embedded with `sentence-transformers`, and stored in a local Chroma vector database at `.freddy/vector_store`.

### Indexed knowledge sources

| Folder | Topics |
|---|---|
| `nmap/` | NIST SP 800-115 (security testing), NIST SP 800-53r5 (controls), RFC 6335 (ports) |
| `wireshark/` | Wireshark User Guide, RFC 791 (IP), RFC 768 (UDP) |
| `linux/` | NIST SP 800-123 (server security), SP 800-190 (containers), SP 800-207 (zero trust) |
| `networking/` | RFC 793 (TCP), RFC 1035 (DNS), RFC 2616 (HTTP), NIST SP 800-41r1 (firewalls) |
| `web_security/` | OWASP Top 10 2021, NIST SP 800-44v2 (web servers), SP 800-95 (web services) |
| `log_analysis/` | NIST SP 800-92 (log management), RFC 5424 (syslog), RFC 3164 (BSD syslog) |
| `incident_response/` | NIST SP 800-61r2 (incident handling), SP 800-86 (forensics) |
| `threat_detection/` | NIST SP 800-94 (IDPS), SP 800-83r1 (malware), SP 800-150 (threat intel) |
| `hardening/` | NIST SP 800-128 (config mgmt), SP 800-77r1 (IPsec), SP 800-52r2 (TLS) |
| `vulnerabilities/` | NIST SP 800-40r4 (patching), SP 800-30r1 (risk), SP 800-171r2 (CUI) |
| `john_the_ripper/` | NIST SP 800-63B (authentication), SP 800-132 (password key derivation) |

### How to search the knowledge base

```bash
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py knowledge-search "How do I detect SQL injection in logs?"
python3 freddy.py knowledge-search "What is zero trust architecture?"
python3 freddy.py knowledge-search "TLS best practices for Ubuntu"
```

Tips for better results:
- Include context like OS, tool, or protocol (Ubuntu, OpenSSL, Docker, iptables)
- Ask one focused question per query
- Refine and re-ask with more detail if needed

### How to add your own documents

Freddy supports **PDF**, **Markdown**, and **plain text** files.

1. Place the file in the matching subfolder:
   ```
   knowledge/nmap/my_nmap_guide.pdf
   knowledge/linux/hardening_checklist.md
   knowledge/web_security/xss_reference.txt
   ```
2. Rebuild the index:
   ```bash
   python3 freddy.py learn
   ```
3. Verify indexing:
   ```bash
   python3 freddy.py knowledge-search "topic from your document"
   ```

Freddy assigns the category automatically from the subfolder name.

### Knowledge folder structure

```text
knowledge/
├── networking/          TCP/IP, DNS, routing, firewalls
├── linux/               Linux administration, hardening, permissions
├── ubuntu/              Ubuntu-specific guides
├── wireshark/           Packet capture and protocol analysis
├── nmap/                Port scanning, service detection
├── nikto/               Web server scanning
├── gobuster/            Directory and DNS brute-forcing
├── ffuf/                Web fuzzing
├── tcpdump/             Command-line packet capture
├── metasploit/          Exploitation and post-exploitation
├── burpsuite/           Web application testing
├── hydra/               Credential brute-forcing
├── john_the_ripper/     Password cracking
├── aircrack/            Wireless security
├── dns_tools/           DNS enumeration and reconnaissance
├── web_security/        OWASP, web vulnerabilities, authentication
├── log_analysis/        auth.log, nginx, apache, IDS logs
├── incident_response/   IR playbooks and triage guides
├── threat_detection/    IDS/IPS, malware, continuous monitoring
├── hardening/           Configuration management, TLS, IPsec
├── vulnerabilities/     CVEs and vulnerability intelligence
├── security_basics/     Foundational cybersecurity concepts
└── (your custom folders)
```

### Downloading the knowledge library

Freddy includes an automated downloader for official NIST, IETF, and OWASP documents:

```bash
python3 download_freddy_knowledge.py    # Download PDFs
python3 freddy.py learn                 # Rebuild index after download
```

The downloader fetches from NIST CSRC, IETF RFC Editor, and the Wireshark project. It skips existing files, verifies PDFs, and retries on errors.

A GitHub Actions workflow (`.github/workflows/knowledge-sync.yml`) can automate this weekly. After it runs, just `git pull` on any machine.

---

## 🗂️ Memory System

Freddy remembers every scan in a SQLite database at `memory/freddy_memory.db`.

### What gets saved

| Field | Description |
|---|---|
| Target | Hostname or IP address |
| Timestamp | When the scan ran |
| Command | Which command was used |
| Findings | AI-extracted structured findings (JSON) |
| Severity | Overall severity level |
| Remediation | Summarized fix guidance |
| Raw output | Path to saved tool output in `data/raw/` |

### Cross-scan correlation

Before every analysis, Freddy checks the database for prior scans of the same target. If history exists, it injects a correlation summary into the AI prompt. This detects:

- Ports remaining exposed across multiple scans
- Recurring vulnerability findings over weeks or months
- Unresolved issues that appeared in 3+ scans

### Deduplication

If findings are identical to the last scan of the same target, Freddy updates the timestamp and increments the scan counter instead of creating a duplicate.

### Viewing history

```bash
python3 freddy.py history                         # All scan history
python3 freddy.py history --target example.com    # History for one target
python3 freddy.py memory-stats                    # Database statistics
```

---

## ⚙️ Configuration

### Optional (for threat intelligence)

| Variable | Purpose | Get it from |
|---|---|---|
| `ABUSEIPDB_API_KEY` | AbuseIPDB lookups | [abuseipdb.com](https://www.abuseipdb.com) |
| `VIRUSTOTAL_API_KEY` | VirusTotal lookups | [virustotal.com](https://www.virustotal.com) |

AlienVault OTX works without an API key.

### Runtime storage

| Path | Contents |
|---|---|
| `.freddy/vector_store/` | Chroma vector database (knowledge index) |
| `memory/freddy_memory.db` | SQLite scan history and correlation data |
| `data/raw/` | Saved raw tool output from each scan |
| `data/reports/` | Generated security reports (Markdown, JSON) |

---

## 📁 Project Structure

```text
Freddy/
├── freddy.py                         Main CLI entry point (Typer + Rich)
├── ai_engine.py                      Claude API integration
├── config.py                         Paths and configuration
├── commands/
│   ├── scan.py                       Nmap scanning
│   ├── recon.py                      Full reconnaissance
│   ├── analyze.py                    File analysis
│   ├── logs.py                       Log file analysis
│   ├── ports.py                      Local port auditing
│   ├── audit.py                      System security audit
│   ├── host_audit.py                 Host-level checks
│   ├── investigate.py                Evidence investigation
│   ├── webcheck.py                   Web security checks
│   ├── tlscheck.py                   TLS/SSL inspection
│   ├── dnscheck.py                   DNS analysis
│   └── whois_lookup.py              WHOIS lookups
├── modules/
│   ├── intelligence_pipeline.py      Main analysis pipeline + SOC enrichment
│   ├── rule_engine.py                Deterministic security rules
│   ├── knowledge_engine.py           RAG knowledge retrieval (ChromaDB)
│   ├── memory_engine.py              SQLite scan history
│   ├── retrieval_formatter.py        Format knowledge for AI context
│   ├── output_formatter.py           Terminal output and startup banner
│   ├── tool_runner.py                Safe external tool execution
│   ├── threat_classifier.py          Threat classification
│   ├── network_analyzer.py           Network analysis utilities
│   ├── log_analyzer.py               Log parsing utilities
│   ├── vulnerability_detector.py     Vulnerability detection
│   ├── file_loader.py                PDF/MD/TXT file loading
│   ├── platform_support.py           Cross-platform tool detection
│   ├── orchestrator.py               Command orchestration
│   ├── mitre_mapper.py               MITRE ATT&CK technique mapping
│   ├── ioc_extractor.py              Indicator of Compromise extraction
│   ├── timeline_reconstructor.py     Incident timeline reconstruction
│   ├── threat_intel.py               Threat intelligence feed lookups
│   ├── siem_correlator.py            Cross-source event correlation
│   ├── auto_investigator.py          Automated multi-tool workflows
│   ├── posture_scorer.py             Security posture scoring (0–100)
│   ├── security_mentor.py            Educational learning notes
│   ├── report_generator.py           Professional report generation
│   └── visualizer.py                 ASCII security visualizations
├── knowledge/                         Cybersecurity reference documents
├── vulnerabilities/                   Vulnerability intelligence files
├── prompts/
│   └── system_prompt.txt             AI system prompt
├── samples/                           Sample files for testing
├── questions/                         2,280 knowledge-test questions
├── data/
│   ├── raw/                           Saved tool output per scan
│   └── reports/                       Generated security reports
├── memory/
│   └── freddy_memory.db              SQLite history database
└── .freddy/
    └── vector_store/                  Chroma knowledge index
```

---

## 💻 Running Freddy on Different Platforms

### Linux (recommended)

All commands work natively. This is the best environment for Freddy.

```bash
python3 freddy.py scan 192.168.1.10
./freddy scan 192.168.1.10
```

### macOS

Most commands work if the underlying tools are installed (`nmap`, `openssl`, `dig`, `whois`, `curl`). Install via Homebrew:

```bash
brew install nmap
```

### Windows

Use PowerShell or Command Prompt:

```powershell
python freddy.py scan 192.168.1.10
freddy.bat scan 192.168.1.10
./freddy.ps1 scan 192.168.1.10
```

Freddy checks common install locations outside `PATH` for tools like `nmap`, `openssl`, `dig`, `whois`, `curl`, `whatweb`, and `nikto`.

**Note:** `ports` and `audit` commands are best run in Linux or WSL because they use Linux-native commands (`ss`, `systemctl`, `ufw`, `iptables`).

### Kali Linux (quick start)

```bash
cd /home/<your-user>/Freddy
git pull --ff-only origin main

python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt

python3 freddy.py learn
python3 freddy.py --help
```

### Launcher scripts

| Script | Platform |
|---|---|
| `freddy` | Linux / macOS |
| `freddy.bat` | Windows CMD |
| `freddy.ps1` | PowerShell |

To add Freddy to your shell `PATH`, create an alias or add the project folder to `PATH`.

---

## 🛠️ Example Workflows

### Workflow 1: Scan a server and get a full report

```bash
python3 freddy.py scan 192.168.1.10
# → Freddy runs Nmap, applies rules, enriches with MITRE ATT&CK,
#   extracts IOCs, scores posture, and generates AI analysis

python3 freddy.py report samples/sample_nmap.txt
# → Exports a professional Markdown report to data/reports/
```

### Workflow 2: Investigate a suspicious log file

```bash
python3 freddy.py logs /var/log/auth.log
# → Parses the log, detects brute-force patterns, builds timeline,
#   maps to ATT&CK, correlates events, and provides remediation

python3 freddy.py ioc-extract /var/log/auth.log
# → Lists all IPs, domains, and suspicious indicators found

python3 freddy.py threat-intel 45.33.32.156
# → Checks the suspicious IP against AbuseIPDB, VirusTotal, OTX
```

### Workflow 3: Full automated investigation of a target

```bash
python3 freddy.py auto-investigate example.com
# → Runs Nmap + web check + TLS + DNS + WHOIS + Nikto
# → Combines all evidence through the full SOC pipeline
# → Produces one comprehensive analysis with all enrichments
```

### Workflow 4: Track security posture over time

```bash
python3 freddy.py scan 192.168.1.10          # Week 1
python3 freddy.py scan 192.168.1.10          # Week 2, Freddy notes recurring issues
python3 freddy.py history --target 192.168.1.10   # Review scan history
python3 freddy.py posture samples/latest.txt       # Check current score
```

### Workflow 5: Learn about a security topic

```bash
python3 freddy.py knowledge-search "How do I harden SSH on Ubuntu?"
python3 freddy.py knowledge-search "What is the OWASP Top 10?"
python3 freddy.py knowledge-search "container security best practices"
```

---

## 🔧 Troubleshooting

### ModuleNotFoundError: No module named typer

Dependencies not installed in your active Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```

### No space left on device (nvidia_cublas_cu12)

Install CPU-only PyTorch instead:

```bash
pip uninstall -y torch torchvision torchaudio nvidia-cublas-cu12 nvidia-cudnn-cu12 nvidia-cuda-runtime-cu12 nvidia-cufft-cu12 nvidia-curand-cu12 nvidia-cusolver-cu12 nvidia-cusparse-cu12 nvidia-nccl-cu12 nvidia-nvtx-cu12 triton
rm -rf ~/.cache/pip
pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch torchvision torchaudio
pip install --no-cache-dir -r requirements.txt
```

### Learn command looks stuck

The first run downloads the embedding model and indexes all documents. This is normal on CPU. Check progress:

```bash
watch -n 3 'du -sh .freddy/vector_store'
```

If no change for 10+ minutes, rerun:

```bash
python3 -u freddy.py learn
```

### Hugging Face warning about unauthenticated requests

Informational only, Freddy works without a token. With a token, downloads are faster.

### PDF dependencies

If PDF loading fails:

```bash
pip install PyMuPDF pdfminer.six
```

---

## 🧪 Testing the Knowledge Base

A pre-generated question bank with **2,280 cybersecurity questions** is included for testing knowledge-search quality.

- **24 topics**: SSH, OWASP, TLS, Firewalls, Containers, Network Protocols, etc.
- **12 question intents**: what-is, how-fix, best-practices, commands, compliance, incident-response, etc.
- **3 difficulty levels**: Beginner (402), Intermediate (1,104), Advanced (774)
- **168 platform/tool variations**: Ubuntu, OpenSSL, Docker, iptables, JWT, etc.

Files:
- `questions/question_bank.jsonl` (JSON Lines)
- `questions/question_bank.csv` (CSV)

Regenerate with custom parameters:

```bash
python3 generate_question_bank.py --format both
```

See [questions/README.md](questions/README.md) for testing scripts and validation methods.

---

## 🛡️ Defensive Use Only

Freddy is intended for authorized defensive cybersecurity work only. Use it for detection, interpretation, hardening, remediation, and incident response support in environments you own or are explicitly authorized to assess.
