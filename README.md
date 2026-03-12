# Freddy

Freddy is a knowledge-driven AI cybersecurity copilot for authorized defensive environments. It combines local tool output, deterministic rule checks, retrieval from a local cybersecurity knowledge base, vulnerability intelligence, and operational memory to produce stronger and more consistent security analysis.

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
Security Tools / Logs / Scan Results
                |
                v
          Freddy CLI Layer
                |
                v
     Pre-AI Intelligence Layer
     |- Rule Engine
     |- Knowledge Retrieval Engine
     |- Vulnerability Intelligence Library
     `- Memory Engine
                |
                v
         AI Analysis Engine
                |
                v
     Structured Security Report
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
5. Compose a structured AI payload with evidence, rules, knowledge, and task metadata
6. Generate the final report
7. Save a summary to operational memory

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

## How Freddy Memory Works

Freddy stores operational history in SQLite at `.freddy/freddy_memory.db`.

Each record stores:

- target
- timestamp
- command used
- summarized findings
- severity
- remediation summary

This memory is used for analyst review and historical comparison, not model fine-tuning.

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
|- .freddy/
|  |- vector_store/
|  `- freddy_memory.db
`- README.md
```

## New Commands

```bash
python3 freddy.py learn
python3 freddy.py knowledge-search "ssh hardening"
python3 freddy.py history
python3 freddy.py history --target example.com
```

Windows equivalents:

```powershell
python freddy.py learn
python freddy.py knowledge-search "ssh hardening"
python freddy.py history
python freddy.py history --target example.com
./freddy.ps1 info
```

## Existing Analysis Commands

```bash
python3 freddy.py scan <target>
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

## How to Rebuild the Knowledge Index

Whenever you change files in `knowledge/` or `vulnerabilities/`, rebuild the vector index:

```bash
python3 freddy.py learn
```

The command recreates Freddy's local Chroma collection and reindexes every current knowledge file.

## Runtime Storage

Freddy stores local runtime intelligence data here:

- Vector database: `.freddy/vector_store`
- SQLite memory database: `.freddy/freddy_memory.db`

These artifacts are local to the project root and can be retained across runs.

## Platform Notes

- Freddy now detects native Windows terminals and returns clearer guidance for Linux-native workflows instead of failing with confusing tool errors.
- Tool-driven commands such as `scan`, `webcheck`, `tlscheck`, `dnscheck`, and `whois` depend on the underlying security tools being available on the host operating system.
- Linux remains the preferred environment for full host-audit and local-service inspection workflows because commands such as `ss`, `systemctl`, `ufw`, and `iptables` are Linux-native.
- WSL is the best option on a regular Windows computer when you want Freddy's full host-inspection behavior without moving to a separate Linux machine.

## Defensive Use Only

Freddy is intended for authorized defensive cybersecurity work only. Use it for detection, interpretation, hardening, remediation, and incident response support in environments you own or are explicitly authorized to assess.
