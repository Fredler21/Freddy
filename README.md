# Freddy

Freddy is a knowledge-driven AI cybersecurity copilot for authorized defensive environments. It combines local tool output, deterministic rule checks, retrieval from a local cybersecurity knowledge base, vulnerability intelligence, and operational memory to produce stronger and more consistent security analysis.

## What This AI Is For

Freddy is built to help defenders understand security data faster and take action with confidence.

- 🛡️ Explain raw security output in plain language (Nmap, logs, TLS, DNS, web scans)
- 🚨 Detect likely risks and misconfigurations before they are missed
- 📊 Prioritize issues by severity so you fix the most important problems first
- 🧠 Use local cybersecurity knowledge during analysis (NIST, RFCs, OWASP, and more)
- 🕒 Compare current findings with prior scans to catch recurring problems
- ✅ Give step-by-step remediation and verification commands

Freddy is for authorized defensive security work: analysis, hardening, triage, and incident response support.

## Run Freddy From a Normal Terminal

Freddy can be launched from a regular computer terminal without VS Code-specific tooling.

Windows PowerShell or Command Prompt:

```powershell
python freddy.py --help
freddy.bat --help
./freddy.ps1 --help
```

Linux or macOS terminal:

```bash
python3 freddy.py --help
./freddy --help
```

The launcher scripts included in the project root are:

- `freddy.bat` for Windows terminals
- `freddy.ps1` for PowerShell
- `freddy` for Linux and macOS shells

If you want Freddy on your shell `PATH`, place the project folder on `PATH` or create a shell alias to one of those launchers.

## What Works On A Normal Computer Terminal

Works directly on Windows, Linux, and macOS terminals once Python dependencies are installed:

- `learn`
- `knowledge-search`
- `history`
- `info`
- `version`
- `analyze <file>`
- `logs <file>`

Usually works cross-platform if the underlying tool is installed and available on `PATH`:

- `scan <target>` with `nmap`
- `tlscheck <target>` with `openssl`
- `dnscheck <domain>` with `nslookup`, `dig`, or `host`
- `whois <domain>` with `whois`
- `webcheck <target>` with `curl`, `whatweb`, and `nikto`

On Windows, Freddy also checks common install locations outside `PATH` for tools such as `nmap`, `openssl`, `dig`, `host`, `whois`, `curl`, `whatweb`, and `nikto`.

Best run in Linux or WSL because they inspect Linux-native host state:

- `ports`
- `audit`

## Architecture

```text
📥 Security tools, logs, and scan results
                  |
                  v
🖥️ Freddy CLI commands (scan, recon, audit, investigate, analyze)
                  |
                  v
🧩 Pre-AI intelligence layer
   |- 📏 Rule Engine (deterministic checks)
   |- 📚 Knowledge Retrieval Engine (local indexed docs)
   |- 🛠️ Vulnerability Intelligence Library
   `- 🗂️ Memory Engine (history + correlation)
                  |
                  v
🤖 AI Analysis Engine
                  |
                  v
📄 Structured defensive report
   |- Executive summary
   |- Confirmed and suspected findings
   |- Severity + confidence
   |- Root cause
   `- Remediation + verification steps
```

## Core Capabilities

- Learn from local markdown knowledge in `knowledge/` and `vulnerabilities/`
- Retrieve relevant defensive guidance during analysis
- Apply deterministic security rules before model reasoning
- Remember previous scans and findings in SQLite
- Produce richer and more consistent remediation guidance
- Provide dedicated commands for indexing, search, and history review

## Knowledge Base Overview

Freddy loads markdown intelligence from two local folders:

- `knowledge/`: broad defensive reference material such as Linux security, SSH hardening, web security, incident response, and network security
- `vulnerabilities/`: focused vulnerability intelligence such as SSH exposure, weak TLS, Redis exposure, missing security headers, and open ports

These files are chunked, embedded with `sentence-transformers`, and stored in a persistent Chroma vector database.

## How Freddy Learns

Freddy does not fine-tune the model. Instead, it builds a local retrieval index:

1. Load markdown files from `knowledge/` and `vulnerabilities/`
2. Split long files into retrieval chunks
3. Embed chunks with the configured sentence-transformer model
4. Persist embeddings in Chroma under `.freddy/vector_store`
5. Retrieve the most relevant chunks during analysis or explicit search

Build or rebuild the index with:

```bash
python3 freddy.py learn
```

On Windows terminals, use:

```powershell
python freddy.py learn
freddy.bat learn
./freddy.ps1 learn
```

## How Analysis Works

For scan, log, audit, and file analysis commands, Freddy now runs this upgraded flow:

1. Collect raw evidence from tools or files
2. Run the rule engine on the raw evidence
3. Build a retrieval query from the command context and rule findings
4. Retrieve relevant knowledge and vulnerability intelligence
5. Retrieve prior scan history for the same target
6. Compose a structured AI payload with evidence, rules, knowledge, history, and task metadata
7. Generate the final report
8. Save structured findings and raw output to memory

## Rule Engine

The rule engine inspects evidence before AI reasoning. Included rules cover:

- Port 22 exposure and possible public SSH risk
- Port 21 FTP exposure
- Port 23 Telnet exposure
- Port 3306 MySQL exposure
- Port 5432 PostgreSQL exposure
- Port 6379 Redis exposure
- Port 9200 Elasticsearch exposure
- Multiple failed login attempts and brute-force indicators
- Repeated 401, 403, and 404 patterns in web logs
- Admin-like endpoint exposure or probing

## Vulnerability Intelligence Library

The `vulnerabilities/` folder acts as Freddy's focused security intelligence layer. Relevant files are retrieved automatically when evidence suggests:

- SSH exposure
- Weak TLS
- Open ports and sensitive listeners
- Redis or MySQL exposure
- Missing security headers

## Freddy Memory System

Freddy builds long-term structured memory of every scan it performs. Each analysis saves:

- The target hostname or IP
- Timestamp of the scan
- Command used
- AI-extracted structured findings as a JSON list
- Severity level
- Summarized remediation guidance
- Path to the raw tool output file

Raw tool output is saved to `data/raw/` for offline review. The structured database lives at `memory/freddy_memory.db`.

Before every analysis, Freddy queries that database for the same target. If prior records exist, a correlation and history summary is injected into the AI prompt so the model can note recurring or unresolved issues.

### Deduplication

If the structured findings for the same target are identical to the most recent stored record, Freddy updates the timestamp and increments the scan counter rather than creating a duplicate row.

### Correlation

Freddy detects patterns such as:

- Port 22 remaining exposed across multiple scans
- Recurring vulnerability findings over weeks or months
- Unresolved issues that have appeared in three or more scans

These patterns give the AI model richer context when generating its report.

### View history

```bash
python3 freddy.py history
python3 freddy.py history --target example.com
```

### View memory statistics

```bash
python3 freddy.py memory-stats
```

Outputs:

- Total scans stored
- Unique targets tracked
- Most frequently seen findings across all scans

## How Freddy Memory Works

Freddy stores operational history in SQLite at `memory/freddy_memory.db` using two tables.

`scans` table columns:

- id
- target
- timestamp
- command
- raw_output_path
- summary
- severity
- findings (JSON list)
- remediation

`targets` table columns:

- id
- hostname
- first_seen
- last_seen
- scan_count

This memory drives analyst review, historical comparison, correlation detection, and AI context enrichment.

## Project Structure

```text
Freddy/
|- freddy.py
|- ai_engine.py
|- config.py
|- commands/
|- modules/
|  |- knowledge_engine.py
|  |- rule_engine.py
|  |- memory_engine.py
|  |- retrieval_formatter.py
|  `- intelligence_pipeline.py
|- knowledge/
|- vulnerabilities/
|- prompts/
|- samples/
|- data/
|  |- raw/          <- raw tool output saved per scan
|  `- reports/      <- structured report storage
|- memory/
|  `- freddy_memory.db
|- .freddy/
|  `- vector_store/
`- README.md
```

## New Commands

```bash
python3 freddy.py learn
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py history
python3 freddy.py history --target example.com
python3 freddy.py memory-stats
```

Windows equivalents:

```powershell
python freddy.py learn
python freddy.py knowledge-search "ssh hardening"
python freddy.py history
python freddy.py history --target example.com
python freddy.py memory-stats
./freddy.ps1 info
```

## Existing Analysis Commands

```bash
python3 freddy.py scan <target>
python3 freddy.py recon <target>
python3 freddy.py host-audit
python3 freddy.py investigate <file>
python3 freddy.py ports
python3 freddy.py analyze <file>
python3 freddy.py logs <file>
python3 freddy.py audit
python3 freddy.py webcheck <target>
python3 freddy.py tlscheck <target>
python3 freddy.py dnscheck <domain>
python3 freddy.py whois <domain>
```

## Example Usage

Index the knowledge base:

```bash
python3 freddy.py learn
```

Search the local security knowledge base:

```bash
python3 freddy.py knowledge-search "ssh hardening"
```

Review Freddy history:

```bash
python3 freddy.py history
python3 freddy.py history --target example.com
```

Analyze a sample log with the upgraded pipeline:

```bash
python3 freddy.py analyze samples/sample_auth.log
```

Run a local port review with rules, retrieval, and memory enabled:

```bash
python3 freddy.py ports
```

## How to Add Knowledge Files

1. Add a new markdown file to `knowledge/` for broad guidance or `vulnerabilities/` for focused issue intelligence
2. Use clear headings and concise defensive guidance
3. Rebuild the index with `python3 freddy.py learn`
4. Use `python3 freddy.py knowledge-search "<topic>"` to validate retrieval quality

## Downloading the Cybersecurity Knowledge Library

Freddy ships with an automated downloader that fetches real PDF documents from
official sources (NIST CSRC, IETF RFC Editor, Wireshark project) into the
correct knowledge subfolders.

### Run the downloader

```bash
python3 download_freddy_knowledge.py
```

The script will:

- Create any missing knowledge subfolders automatically
- Skip files that are already present and valid
- Show per-file download progress
- Verify each file is a valid PDF before saving
- Retry up to 3 times on network errors
- Print a summary of downloaded / skipped / failed files

### After downloading, build the index

```bash
python3 freddy.py learn
```

### What gets downloaded

| Folder | Document |
|---|---|
| `nmap/` | NIST SP 800-115 (security testing), NIST SP 800-53r5 (controls), RFC 6335 (port assignments) |
| `wireshark/` | Official Wireshark User Guide, RFC 791 (IP), RFC 768 (UDP) |
| `linux/` | NIST SP 800-123 (server security), SP 800-190 (containers), SP 800-207 (zero trust) |
| `ubuntu/` | NIST SP 800-123, SP 800-190 (containers), SP 800-70r4 (OS checklists) |
| `networking/` | RFC 793 (TCP), RFC 1035 (DNS), RFC 2616 (HTTP/1.1), RFC 791 (IP), RFC 2328 (OSPF), RFC 4271 (BGP), NIST SP 800-41r1 (firewalls) |
| `web_security/` | OWASP Top 10 2021, NIST SP 800-44v2 (web servers), SP 800-95 (web services) |
| `log_analysis/` | NIST SP 800-92 (log management), RFC 5424 (syslog), RFC 3164 (BSD syslog) |
| `incident_response/` | NIST SP 800-61r2 (incident handling), SP 800-86 (forensics) |
| `threat_detection/` | NIST SP 800-94 (IDPS), SP 800-83r1 (malware), SP 800-150 (threat intel), SP 800-137 (continuous monitoring) |
| `hardening/` | NIST SP 800-128 (config management), SP 800-77r1 (IPsec VPN), SP 800-70r4 (checklists), SP 800-52r2 (TLS) |
| `vulnerabilities/` | NIST SP 800-40r4 (patch mgmt), SP 800-30r1 (risk), SP 800-53r5 (controls), SP 800-171r2 (CUI) |
| `john_the_ripper/` | NIST SP 800-63B (authentication), SP 800-132 (password key derivation), SP 800-63-3 (digital identity) |

All sources are freely licensed government or open-source documentation.
If a URL returns a 404, update the `CATALOG` list at the top of `download_freddy_knowledge.py`.

### GitHub-only automation (no manual downloader run on devices)

Freddy can keep the extracted `.txt` knowledge library up to date directly from GitHub Actions.
This means your devices can simply `git pull` the generated text files from `knowledge/`.

Workflow file:

- `.github/workflows/knowledge-sync.yml`

How it works:

1. Runs on a schedule (weekly) or manual dispatch
2. Executes `python download_freddy_knowledge.py`
3. Extracts PDF content into `.txt` files in the matching `knowledge/*/` folders
4. Commits and pushes changed files back to the repository

How to run it manually from GitHub:

1. Open your repository on GitHub
2. Go to **Actions**
3. Select **Sync Freddy Knowledge Library**
4. Click **Run workflow**

After it completes, pull updates on any machine:

```bash
git pull origin main
```

## Quick Start on Kali Linux

Use this sequence on a fresh Kali machine after cloning or pulling updates:

```bash
cd /home/<your-user>/Freddy
git fetch origin
git checkout main
git pull --ff-only origin main

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt

python3 freddy.py learn
python3 freddy.py --help
```

## Troubleshooting

### ModuleNotFoundError: No module named typer

This means dependencies were not installed in your active Python environment.

```bash
cd /home/<your-user>/Freddy
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```

### No space left on device while installing nvidia_cublas_cu12

Your system is trying to install GPU CUDA wheels. If you do not need GPU acceleration, install CPU-only PyTorch.

```bash
pip uninstall -y torch torchvision torchaudio nvidia-cublas-cu12 nvidia-cudnn-cu12 nvidia-cuda-runtime-cu12 nvidia-cufft-cu12 nvidia-curand-cu12 nvidia-cusolver-cu12 nvidia-cusparse-cu12 nvidia-nccl-cu12 nvidia-nvtx-cu12 triton
rm -rf ~/.cache/pip
pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch torchvision torchaudio
pip install --no-cache-dir -r requirements.txt
```

### Learn command looks stuck after model download

The first run may take a while on CPU with a large knowledge set. This is normal.

Check that indexing is still active:

```bash
ps -ef | grep "freddy.py learn" | grep -v grep
top
watch -n 3 'du -sh .freddy/vector_store'
```

If there is no change for 10+ minutes, stop and rerun with unbuffered output:

```bash
python3 -u freddy.py learn
```

### Hugging Face warning about unauthenticated requests

This warning is informational. Freddy still works without a token.

- Without token: lower rate limits, slower model downloads.
- With token: faster and more reliable downloads from Hugging Face.

### Where extracted knowledge text is stored

The GitHub knowledge workflow stores extracted text directly in:

- `knowledge/*/*.txt`

Examples:

- `knowledge/nmap/nist_sp800-115_security_testing.txt`
- `knowledge/web_security/nist_sp800-44v2_web_server_security.txt`
- `knowledge/vulnerabilities/nist_sp800-40r4_patch_management.txt`

After pulling from GitHub, run:

```bash
python3 freddy.py learn
```

### Verify knowledge is searchable

```bash
python3 freddy.py knowledge-search "patch management"
python3 freddy.py knowledge-search "tls hardening"
```

## Adding Cybersecurity Knowledge Documents

Freddy can ingest and index cybersecurity reference material in **PDF, Markdown, and plain text** formats. Place documents into the relevant folder under `knowledge/` and re-run the index command.

### Knowledge folder structure

```text
knowledge/
|- networking/          <- TCP/IP, routing, packet analysis
|- linux/               <- Linux administration, hardening, permissions
|- ubuntu/              <- Ubuntu-specific guides
|- wireshark/           <- Packet capture and protocol analysis
|- nmap/                <- Port scanning, service detection
|- nikto/               <- Web server scanning
|- gobuster/            <- Directory and DNS brute-forcing
|- ffuf/                <- Web fuzzing
|- tcpdump/             <- Command-line packet capture
|- metasploit/          <- Exploitation and post-exploitation
|- burpsuite/           <- Web application testing
|- hydra/               <- Credential brute-forcing
|- john_the_ripper/     <- Password cracking
|- aircrack/            <- Wireless security
|- dns_tools/           <- DNS enumeration and reconnaissance
|- web_security/        <- OWASP, web vulnerabilities, authentication
|- log_analysis/        <- auth.log, nginx, apache, IDS logs
|- incident_response/   <- IR playbooks and triage guides
|- vulnerabilities/     <- Specific CVEs and vulnerability intel
|- security_basics/     <- Foundational cybersecurity concepts
```

### Supported file types

| Extension | How it is loaded |
|---|---|
| `.pdf` | Text extracted with PyMuPDF (falls back to pdfminer.six) |
| `.md` | Read directly |
| `.txt` | Read directly |

### How to add documents

1. Place the PDF (or `.md` / `.txt`) into the matching subfolder:
   ```
   knowledge/nmap/nmap_cheat_sheet.pdf
   knowledge/wireshark/protocol_analysis_guide.pdf
   knowledge/linux/linux_hardening.md
   ```
2. Rebuild the index:
   ```bash
   python3 freddy.py learn
   ```
3. Verify the document was indexed:
   ```bash
   python3 freddy.py knowledge-search "nmap scan types"
   ```

Freddy assigns the **category** automatically from the subfolder name. A file placed in `knowledge/nmap/` gets `category: nmap`. This category is stored with each chunk and surfaced in knowledge-search results and AI analysis context.

### Install PDF dependencies

If not already installed:

```bash
pip install PyMuPDF pdfminer.six
```

Or reinstall all requirements:

```bash
pip install -r requirements.txt
```

## How to Rebuild the Knowledge Index

Whenever you change files in `knowledge/` or `vulnerabilities/`, rebuild the vector index:

```bash
python3 freddy.py learn
```

The command recreates Freddy's local Chroma collection and reindexes every current knowledge file.

## Runtime Storage

Freddy stores local runtime intelligence data here:

- Vector database: `.freddy/vector_store`
- SQLite memory database: `memory/freddy_memory.db`
- Raw tool output: `data/raw/`
- Structured reports: `data/reports/`

These artifacts are local to the project root and can be retained across runs.

## Platform Notes

- Freddy now detects native Windows terminals and returns clearer guidance for Linux-native workflows instead of failing with confusing tool errors.
- Tool-driven commands such as `scan`, `webcheck`, `tlscheck`, `dnscheck`, and `whois` depend on the underlying security tools being available on the host operating system.
- Linux remains the preferred environment for full host-audit and local-service inspection workflows because commands such as `ss`, `systemctl`, `ufw`, and `iptables` are Linux-native.
- WSL is the best option on a regular Windows computer when you want Freddy's full host-inspection behavior without moving to a separate Linux machine.

## Defensive Use Only

Freddy is intended for authorized defensive cybersecurity work only. Use it for detection, interpretation, hardening, remediation, and incident response support in environments you own or are explicitly authorized to assess.
